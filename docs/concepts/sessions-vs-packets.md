# Sessions vs. Packets (Live Mode vs. Packet Mode)

> Real-time bidirectional and store-and-forward are the **same**
> protocol with different transport assumptions.

## What problem this solves

Most authentication protocols assume a live network: you handshake,
you exchange messages, you tear down. That works for a browser
hitting a server. It falls over when:

- An LTE modem on a marine telemetry buoy gets one window of
  connectivity per hour.
- A LoRa node sends a 51-byte payload that arrives, maybe, three
  hops later.
- An MSP technician needs to deliver a signed approval to a
  customer's air-gapped facility on a USB stick.
- A code-signing CI job wants to issue a capability that the
  release box will pick up six hours later, after a manual review.

Designing two unrelated protocols — one for live, one for offline —
doubles your spec, doubles your reference implementations, and
guarantees the two will diverge in subtle and exploitable ways.

TrustForge instead defines **two modes** that share types,
schemas, signing rules, and authority semantics: **Live Mode**
(sessions) and **Packet Mode** (`.tfpkt`). They differ only in
transport assumptions. The same actor URIs, the same capabilities,
the same proof events flow through both. See
`TF-0003-proofwire-transport.md`.

## Live Mode (sessions)

A **session** is a live, authenticated, bidirectional trust
relationship between two actor instances. Sessions support:

- mutual actor authentication (X25519 key exchange, ed25519
  signature on the handshake);
- AEAD-encrypted frames (ChaCha20-Poly1305 or XChaCha20-Poly1305);
- in-band rekeying and ratcheting;
- transport binding (the session is *bound* to a TLS exporter, a
  SPIFFE SVID, a WebSocket origin, …);
- session migration (one session can move from WebSocket to QUIC
  to native ProofWire without losing its lineage);
- continuous re-authorization (see
  `docs/concepts/continuous-authorization.md`);
- in-band proof event emission;
- relay forwarding (the session can traverse one or more relay
  actors that cannot decrypt the frames).

The reference implementation is in
`tools/tf-session/` (TS) — a WebSocket carrier today, with native
ProofWire and QUIC scheduled. Cross-language parity is enforced
via `conformance/session-vectors.yaml`.

The keying details: X25519 + HKDF-SHA256 + ChaCha20-Poly1305 +
ed25519 for the classical suite; ml-dsa-65 (FIPS 204) added for the
hybrid PQ side per the post-quantum roadmap. No bespoke crypto —
this is a hard rule (see `SECURITY.md`).

## Packet Mode (`.tfpkt`)

A **packet** is a standalone signed/encrypted object that can be
delivered offline, stored, transferred via USB or QR code, queued
on a relay, fragmented for LoRa, or held for replay protection. A
packet carries:

- the same actor URIs and authority references as a session frame;
- a fresh per-packet AEAD key (or a multi-recipient envelope when
  destined for several actors);
- ed25519 signatures over the canonical bytes;
- expiry, nonce, and replay-protection metadata;
- an optional priority class (P0–P5) — see
  `TF-0003-proofwire-transport.md`.

The reference implementation lives in `tools/tf-packet/`, including
fragmentation/reassembly and a LoRa simulator. Bundle format is
specified by `schemas/packet.schema.json` and parity-tested.

## When to use which

| Use case                                  | Mode    |
|-------------------------------------------|---------|
| Browser → backend RPC                     | Live    |
| AI agent → tool call within a session     | Live    |
| Service mesh sidecar enforcement          | Live    |
| One-shot signed approval delivered later  | Packet  |
| LoRa mesh telemetry from sensors          | Packet  |
| USB-stick delivery to air-gapped host     | Packet  |
| Revocation distribution over fan-out mesh | Packet  |
| Live remote-shell session                 | Live    |
| Compliance evidence bundle for audit      | Packet  |
| Backend-to-backend high-throughput stream | Live    |

You do not have to choose globally. A deployment can mix: a live
session can encapsulate packets bound for offline destinations, and
a packet stream can carry session-resumption metadata so a previously
live session can pick up where it left off after an outage.

## Worked example: a deferred approval

A field technician is on an oil rig with one hour of satellite
connectivity per day. They need to approve a firmware update that
the on-shore CI job will install. Sequence:

1. CI job publishes a packet
   `firmware-update-request.tfpkt` to the technician's relay queue.
   The packet contains the action (`firmware.install`), the target
   device URI, and the policy decision requiring approval.
2. Technician's daemon picks up the packet during the connectivity
   window, displays the approval ceremony locally, and on YubiKey
   tap signs an `approval-grant.tfpkt`.
3. The approval packet is queued on the rig's outbound relay.
4. Next connectivity window, the relay forwards the packet to the
   CI job's daemon. The daemon verifies:
   - signature against technician's pinned key,
   - approval ceremony matches the original request id,
   - approval has not expired,
   - approval has not been revoked since issuance (consult the
     offline revocation list — see `docs/concepts/offline-
     revocation-lists.md`).
5. CI job emits an `action.executed` proof event referencing the
   approval, and the firmware is rolled.

Notice: the same authority semantics apply. The approval is signed
exactly the way an in-session click-approval would be signed. The
verifier checks the same way. The proof event has the same shape.
The only difference is *when* the bytes flowed through which
transport.

## Migration between modes

A session can degrade to packet mode when connectivity drops and
upgrade back when it returns. The `session.migrated` proof event
records the lineage: same actor instances, new transport binding,
fresh AEAD epoch. See "Session migration" in `DECISIONS.md`.

A packet can spawn a live session: receiving a packet that
references an open session-resumption token allows the recipient to
re-establish a live channel using the resumption material. Useful
for "ping me when you have signal again" patterns.

## Common misconceptions

**"Sessions and packets are unrelated protocols."** They share types,
schemas, signing rules, capability semantics, and proof-event
structure. They differ in transport assumptions and AEAD framing,
not in identity or authority.

**"Packets are insecure because they're not part of a live
handshake."** A packet's security properties come from per-packet
freshness (nonces and expiries), signed binding to a target
audience (subject + audience fields), and the receiver's revocation
view. The *threat model* is different (replay risk and offline
revocation timing matter more) but the protections are
intentional, not accidental — see `replay-attack`,
`relay-forwarding-authority-confusion`, and `aead-nonce-discipline`
in `.tf/threat-model.yaml`.

**"I should just use TLS for everything."** TLS is a great
transport; TrustForge has a TLS bridge (`docs/bridges/tls-did-
matrix-bridge.md`). But TLS does not give you actor-instance URIs,
capability tokens, signed authority chains, proof events, or
relay-forwarding-authority separation. Use TLS *and* TrustForge.

**"Packet mode is just for IoT."** Packet mode is also for
compliance evidence (the `.tfbundle` is packet-style), for
delegation across organizational boundaries (a signed delegation
packet hand-carried to the recipient), and for revocation
distribution at scale.

**"A session and a packet emit different proof events."** The
event types differ (`session.frame.delivered` vs.
`packet.delivered`) but the action-level events
(`policy.decision`, `action.executed`, `approval.granted`) are
identical. An auditor reading the ledger cannot tell from those
events whether the underlying transport was live or packet — and
they should not need to.

## Where to look next

- `docs/concepts/relays-as-actors.md` — how relays move both
  sessions and packets without seeing payloads.
- `docs/concepts/continuous-authorization.md` — sessions get
  re-authorized continuously; packets get re-checked at delivery.
- `docs/concepts/offline-revocation-lists.md` — packet-mode
  revocation distribution.
- `TF-0003-proofwire-transport.md` — normative spec.
- `tools/tf-session/` and `tools/tf-packet/` — reference
  implementations.
- `conformance/session-vectors.yaml` and packet vectors.
