# Data flows

This page documents every major flow that crosses a TrustForge
boundary. For each flow it shows the actors, the messages, the
signing keys involved, and the proof event(s) emitted. Layer numbers
refer to the 12 layers in
[`system-overview.md`](system-overview.md).

The flows are presented in dependency order: identity first, then
sessions, then policy, then proof, then federation, then evidence.

## Flow A — Live mode handshake

Layers exercised: 1, 2, 3, 4, 9. Spec:
[TF-0003 §3](../specs/TF-0003-proofwire-transport.md). Code:
`crates/tf-session/`, `tools/tf-session/`,
`tools/tf-daemon/src/session/`.

```mermaid
sequenceDiagram
    autonumber
    participant I as Initiator<br/>tf:instance:agent:.../A
    participant R as Responder<br/>tf:instance:service:.../B
    participant L as Local proof ledger

    I->>R: ClientHello (actor URI, ephemeral X25519 pk, suites, nonce_i)
    R->>I: ServerHello (actor URI, ephemeral X25519 pk, chosen suite, nonce_r)
    Note over I,R: Both derive session_secret via X25519 + HKDF-SHA256
    I->>R: ClientAuth (ed25519 sig over transcript || nonce_r)
    R->>I: ServerAuth (ed25519 sig over transcript || nonce_i)
    Note over I,R: AEAD frames (ChaCha20-Poly1305) begin
    R->>L: pe.session.opened (signed by R)
    I->>L: pe.session.opened (signed by I)
```

Signed material:

- ClientAuth and ServerAuth sign the running transcript hash (SHA-256
  over canonical-JSON of every prior frame) plus the peer's nonce.
  This is the layer-4 binding between actor identity and key exchange.
- The transcript hash is exported (RFC 5705 / RFC 8446 exporter
  keying) so downstream proof events can bind to the session without
  re-deriving the secret.

## Flow B — Packet sign and verify

Layers exercised: 1, 5, 6, 9. Spec:
[TF-0003 §4](../specs/TF-0003-proofwire-transport.md). Code:
`tools/tf-packet/`, `crates/tf-types/src/packet.rs`.

```mermaid
sequenceDiagram
    autonumber
    participant S as Sender (offline)
    participant T as Transport (LoRa, sneakernet, Matrix relay)
    participant V as Verifier
    participant L as V's local ledger

    S->>S: Compose Packet { from, to, ts, nonce, payload, caps }
    S->>S: Sign canonical-JSON with sender ed25519 secret
    S->>S: (Optional) AEAD-seal payload to recipient X25519 pk
    S->>T: Emit .tfpkt frame (magic + len + CBOR)
    T->>V: Deliver (possibly delayed, fragmented, mesh-forwarded)
    V->>V: Verify ed25519 sig with sender pubkey
    V->>V: Check nonce against sliding-window cache
    V->>V: Decrypt AEAD payload (if sealed)
    V->>V: Evaluate capabilities (layer 6)
    V->>L: pe.packet.received (signed by V)
```

A relay actor on the path between S and V never holds the AEAD key
when the payload is sealed, but it can sign a `pe.packet.forwarded`
event with its own key so the chain of carriage is recorded. See
[relays-as-actors.md](../concepts/relays-as-actors.md).

## Flow C — `/v1/decide` policy decision

Layers exercised: 6, 7, 9. Spec:
[TF-0004 §5](../specs/TF-0004-capabilities-policy.md). Code:
`tools/tf-daemon/src/admin/decide.ts`,
`crates/tf-cedar/`, `crates/tf-rego/`.

```mermaid
sequenceDiagram
    autonumber
    participant App as App / Adapter
    participant D as tf-daemon
    participant E as Policy engine<br/>(tf-cedar / tf-rego)
    participant L as Proof ledger

    App->>D: POST /v1/decide<br/>{actor, action, target, context}
    D->>D: Resolve actor, instance, trust domain
    D->>D: Pull capabilities (allow_targets) and<br/>negative capabilities (deny_targets)
    D->>E: Evaluate policy with caps + context
    E-->>D: Decision { allow, deny, escalate, approve, log, constrain }
    D->>L: pe.action.allowed | pe.action.denied | pe.action.escalated
    D-->>App: 200 { decision, reasons, proof_event_id }
```

Decision precedence is fixed at the engine layer:

1. Negative capability match → `deny` (regardless of any allow).
2. Approval ceremony required → `escalate` until satisfied.
3. Capability allows the target → `allow` plus any constraints.
4. No matching grant → `deny`.

## Flow D — `/v1/import-credential`

Layers exercised: 1, 6, 10. Spec:
[TF-0009 §4](../specs/TF-0009-compatibility-bridges.md) and the
per-bridge specs in [`../bridges/`](../bridges/). Code:
`tools/tf-daemon/src/admin/bridges/`.

```mermaid
sequenceDiagram
    autonumber
    participant Op as Operator / Adapter
    participant D as tf-daemon
    participant B as Bridge module<br/>(spiffe / oauth / webauthn / tls / did / matrix)
    participant Vault as Vault (sealed file)
    participant L as Proof ledger

    Op->>D: POST /v1/import-credential<br/>{kind, payload}
    D->>B: Dispatch by kind (e.g. "spiffe-svid")
    B->>B: Validate signature / chain / RPID / aud
    B->>B: Map to actor URI per bridge mapping
    B-->>D: { actor_uri, capability_grants, expiry }
    D->>Vault: Persist mapping + bundle
    D->>L: pe.bridge.credential.imported
    D-->>Op: 200 { actor_uri, expires_at }
```

The bridge module is the only place an external credential is
trusted. Once imported, downstream layers see a TrustForge actor URI
and capabilities — they do not see the original SPIFFE SVID, OAuth
token, or WebAuthn assertion. See [`../bridges/`](../bridges/) for
each mapping.

## Flow E — `/v1/proof/sign` and `/v1/proof/verify`

Layers exercised: 9. Spec:
[TF-0005](../specs/TF-0005-proof-events-ledgers.md). Code:
`tools/tf-proof/`, `tools/tf-daemon/src/admin/proofs/`.

```mermaid
sequenceDiagram
    autonumber
    participant Caller as Caller
    participant D as tf-daemon
    participant L as Hash-chained ledger
    participant A as Optional anchor<br/>(RFC 6962 / RFC 3161)

    Caller->>D: POST /v1/proof/sign { event }
    D->>D: Compute event_hash (SHA-256 over canonical JSON)
    D->>L: Append (prev_chain_hash, event_hash, ed25519 sig)
    L-->>D: chain_index, chain_hash
    D-->>Caller: ProofEvent { id, chain_hash, signature }
    Note over D,A: Optional anchor (per profile)
    D->>A: Anchor batch (Merkle root)
    A-->>D: Inclusion proof
    D->>L: Anchor record

    Caller->>D: POST /v1/proof/verify { proof_event }
    D->>D: Verify ed25519 sig on event
    D->>L: Verify event in chain (prev_hash matches)
    D->>A: (If profile requires) verify inclusion proof
    D-->>Caller: { valid: true, level: L0..L5 }
```

The proof level returned (L0–L5) is determined by which checks
passed. See [proof-levels-l0-to-l5.md](../concepts/proof-levels-l0-to-l5.md).

## Flow F — Federation join

Layers exercised: 1, 3, 9, 10. Spec:
[TF-0008](../specs/TF-0008-plugins-extensions.md) §federation, plus
the SPIFFE bridge in [`../bridges/spiffe-bridge.md`](../bridges/spiffe-bridge.md).
Code: `tools/tf-daemon/src/federation/`,
`schemas/federation-attestation.schema.json`.

```mermaid
sequenceDiagram
    autonumber
    participant A as Domain A operator
    participant DA as A's tf-daemon
    participant DB as B's tf-daemon
    participant B as Domain B operator
    participant L as Both ledgers

    A->>DA: tf trust-domain init
    DA-->>A: Domain A pubkey set + bundle
    A->>B: Out-of-band: send Domain A bundle (signed)
    B->>DB: tf trust-domain federate --bundle a-bundle.json
    DB->>DB: Pin A's issuer keys with kid binding
    DB->>L: pe.federation.peer.added
    B->>A: Reciprocal bundle exchange (same flow reversed)
    Note over DA,DB: Both daemons now resolve actors in the peer domain
    DA->>DB: First cross-domain action (live or packet)
    DB->>DB: Verify actor sig with pinned A pubkey set
```

A federated peer is **not** a wildcard authority. Pinned key sets
plus an explicit `kid` (key id) bind the federation to a known set of
roots; rotation requires an explicit operator acknowledgement (see
the `federation-issuer-key-verify` mitigation in
`.tf/threat-model.yaml`).

## Flow G — Evidence assemble

Layers exercised: 9, 12. Spec:
[TF-0012](../specs/TF-0012-compliance-evidence-profile.md). Code:
`tools/tf-evidence/`,
[`../profiles/compliance-evidence-profile.md`](../profiles/compliance-evidence-profile.md).

```mermaid
sequenceDiagram
    autonumber
    participant Op as Operator
    participant E as tf-evidence
    participant L as Proof ledger
    participant A as RFC 3161 / RFC 6962 anchor
    participant V as Verifier (auditor)

    Op->>E: tf evidence assemble<br/>--from t0 --to t1 --recipients X,Y
    E->>L: Pull events in [t0, t1]
    E->>E: Build Merkle tree, redact per policy
    E->>A: (L5) Anchor Merkle root
    A-->>E: Timestamp token + inclusion proof
    E->>E: AEAD-seal bundle to recipient X25519 pubkeys
    E-->>Op: .tfbundle (CBOR + signature trailer)

    Op->>V: Deliver .tfbundle (any channel)
    V->>E: tf evidence verify
    E->>E: Decrypt, verify chain, verify anchor, verify each event
    E-->>V: { valid, redactions_consistent, level: L4|L5 }
```

The bundle format (`.tfbundle`) is documented in the CHANGELOG entry
for B15: magic + u32 BE length + CBOR-encoded `ProofBundle` or
`ProofBundleEncrypted` + optional signature trailer.

## Flow H — Site-to-site `http-bridge` (TF-0013)

Layers exercised: 1, 4, 6, 9. Spec:
[TF-0013](../specs/TF-0013-site-to-site-binary-path.md). Topology:
[`../topologies/site-to-site.md`](../topologies/site-to-site.md).
Code: `tools/tf-daemon/` (binary path),
`crates/tf-session/` (TCP carrier), `crates/tf-proxy/`.

```mermaid
sequenceDiagram
    autonumber
    participant App as Site A application
    participant DA as tf-daemon @ Site A
    participant DB as tf-daemon @ Site B
    participant Up as Site B upstream HTTP service
    participant L as Both proof ledgers

    Note over DA,DB: TLS/TCP, length-delimited frames (TF-0013 §2)
    DA->>DB: Session handshake (TF-0003 §3)
    App->>DA: HTTP request (loopback or UDS)
    DA->>DB: rpc-call kind=http-bridge { method, path, headers }
    DA->>DB: body-chunk frames (more=true)
    DA->>DB: body-chunk frame (more=false)
    DB->>Up: Replay HTTP request
    Up-->>DB: HTTP response
    DB->>DA: response-headers + body-chunk frames
    DA-->>App: HTTP response
    DA->>L: pe.rpc.completed (kind=http-bridge)
    DB->>L: pe.rpc.completed (kind=http-bridge)
```

Every frame on the binary path is AEAD-protected by the layer-4
session keys. The HTTP semantics ride inside; the application is
unaware of the cross-site hop.

## Cross-flow invariants

- Every mutating flow emits at least one signed proof event.
- Every flow that crosses a trust boundary names that boundary in the
  proof event (`session.opened`, `bridge.credential.imported`,
  `federation.peer.added`).
- Every signed object carries the algorithm identifier of the key
  that signed it, so post-quantum hybrid signatures (FIPS-204
  ml-dsa) drop in at the verifier.
- Every flow can be re-run from a packet stream — there is no
  "online-only" decision.
