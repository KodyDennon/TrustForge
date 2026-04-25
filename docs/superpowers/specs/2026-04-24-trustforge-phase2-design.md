# TrustForge Phase 2 — Proof Format Design Spec

**Date:** 2026-04-24
**Status:** Draft, approved for implementation planning
**Scope:** Roadmap Phase 2 (proof event hash-chain, proof log, proof bundle with real signatures + merkle, CLI proof inspect/verify, binary `.tfproof` framing) plus closing the Phase 0 gap of the four missing Rust semantic core modules.

## 1. Purpose

Turn the Phase-0 proof-event / proof-bundle schemas into a working, cryptographically-verifiable proof system. After this phase, TrustForge can:

- Sign individual proof events and verify them.
- Link events into a hash-chain per session / actor.
- Pack events into a bundle with a Merkle root, sign the bundle.
- Write and read append-only `.tflog` files and framed `.tfproof` binary bundles.
- Offer a `tf-proof` CLI that inspects, verifies, and signs bundles.
- Guarantee TS↔Rust signing parity: a bundle signed in one runtime verifies in the other.

## 2. Non-goals

- **No new crypto primitives.** Compose reviewed ones: ed25519 (classical), BLAKE3 and SHA-256 (hashing). Post-quantum ML-DSA is stubbed in the envelope schema (already done in P0); real PQ verification lands in a later phase behind a feature flag.
- **No transparency anchoring (CT-like) client.** The schema carries `transparency_anchor` metadata; Phase 2 neither submits to nor verifies against a transparency log.
- **No distributed proof anchoring / federation.** Local and bundle-level only.
- **No session or packet protocol.** Phase 3+.

## 3. Architecture

Three new vertical layers, each with matched TS and Rust implementations and cross-language parity vectors:

### 3.1 Crypto layer (`crypto`)

Thin abstraction over reviewed primitives. Single trait / interface in each language:

- `Signer.sign(canonical_bytes) -> Signature`
- `Verifier.verify(canonical_bytes, signature) -> Result<()>`
- `Hasher.sha256(bytes) -> HashRef`, `Hasher.blake3(bytes) -> HashRef`

Implementations:

- Rust: `ed25519-dalek` for ed25519; `sha2`, `blake3` crates for hashing.
- TS: `@noble/ed25519` and `@noble/hashes` (dependency-free, audited, WASM-free pure JS — crucial for Bun and browser portability).

Keys are supplied as raw 32-byte ed25519 private/public key bytes. No key derivation or key management here — that's a future concern.

### 3.2 Chain / merkle layer (`chain`)

- **Event hash**: `sha256(canonical_json(event_without_signature))`. The hash used for `parent_hash` chaining and payload references.
- **Chain verification**: given a sequence of events, assert `events[i].parent_hash == sha256(canonical_json(events[i-1] without signature))` for every i > 0 (events[0] has no `parent_hash` or a well-known genesis).
- **Merkle root**: binary Merkle tree over event hashes. Empty tree → sentinel `sha256:0..0`; single-event tree → the event's hash; otherwise pair-and-hash up to the root. If a level has an odd number of nodes, duplicate the last node (the common lightweight convention; documented).
- **Chain hash**: running `sha256(prev_chain_hash || current_event_hash)`, seeded with zero. Useful for lightweight attestation without storing the whole tree.

### 3.3 Format layer (`format`)

- **`.tflog`**: append-only log of proof events. Framing: `4-byte length-prefix (u32 BE)` + `canonical-JSON event bytes`. Magic header at offset 0: `TFLOG\x01` + u16 reserved (`\x00\x00`). Each frame is independently parseable; the file may be truncated at any frame boundary.
- **`.tfproof`**: signed bundle container. Framing:
  - 8-byte magic `TFPROOF\x01`.
  - 4-byte length-prefix (u32 BE) for the canonical-JSON bundle body.
  - Canonical-JSON body (the `proof-bundle.schema.json` document, canonicalized).
  - Trailer: 4-byte length-prefix + raw signature bytes (redundant with the bundle's internal signature, but fast to locate on a streaming read).

Both formats have their own TS and Rust readers/writers with a shared `conformance/framing-vectors.yaml` that pins expected byte output for canonical inputs.

## 4. Schema changes

The Phase 0 `proof-event.schema.json` and `proof-bundle.schema.json` already carry the necessary fields. Phase 2 makes them semantically meaningful without adding or removing fields; the constraints are enforced in code, not in JSON Schema.

One addition: a tiny new schema `proof-log.schema.json` describing the JSON-shape summary of a `.tflog` (used by `tf-proof inspect` to emit a structured view). It lists `{magic, version, event_count, head_hash}` plus a preview of the last few events.

## 5. CLI `tf-proof`

A new workspace package `tools/tf-proof` (TypeScript, Bun) with commands:

- `tf-proof inspect <file>` — decode `.tflog` or `.tfproof`, print structured summary + optionally `--events` to dump all events.
- `tf-proof verify <file> --key <file>` — verify every signature in the file (envelope + bundle-level + hash-chain + merkle root).
- `tf-proof sign --bundle <events-json> --key <privkey-file> [--out file.tfproof]` — sign + write.
- `tf-proof derive-pubkey --key <privkey-file>` — emit the matching public key (base64).
- `tf-proof keygen [--out dir]` — generate a fresh ed25519 key pair.

The CLI prints canonicalized JSON on stdout for easy piping; non-zero exit on any verification failure.

## 6. Rust core-module completion (Phase 0 carry-over)

Four new modules in `crates/tf-types`, each mirroring its TS counterpart 1:1 in surface and behavior:

- `capability.rs` — `constraints_satisfied`, `intersect_constraints`, plus the `EvalContext` struct and minimal glob matcher (ported from TS).
- `delegation.rs` — `walk_chain(chain, now) -> WalkResult`, honouring `expires_at`, `redelegation.allowed`, and `max_depth`.
- `revocation.rs` — `RevocationIndex::from`, `is_revoked`.
- `envelope.rs` — `validate_envelope_shape`, including the "unknown algorithm" warning path.

Unit tests mirror the TS tests 1:1. A shared `conformance/semantics-vectors.yaml` pins inputs and expected outcomes for both runtimes.

## 7. Cross-language parity

Three new parity surfaces on top of the existing canonical-JSON parity:

- **Signature parity**: a fixed keypair + known message must produce the same 64-byte ed25519 signature in both runtimes (deterministic per RFC 8032). Test vector file: `conformance/signature-vectors.yaml`.
- **Chain / merkle parity**: a set of event sequences + expected parent-hash and merkle-root bytes. Vector file: `conformance/chain-vectors.yaml`.
- **Framing parity**: known bundle JSON → known `.tfproof` byte output. Vector file: `conformance/framing-vectors.yaml`.

Both runtimes run each vector set and assert byte equality or verification success.

## 8. Repository additions

```
crates/tf-types/src/
  capability.rs        delegation.rs        revocation.rs        envelope.rs      (Phase 0 carry-over)
  crypto.rs            chain.rs             format.rs                              (Phase 2)
crates/tf-types/Cargo.toml                                                         (+ ed25519-dalek, sha2, blake3)
crates/tf-types/tests/
  semantics.rs         signature_vectors.rs chain_vectors.rs     framing_vectors.rs

tools/tf-types-ts/src/core/
  crypto.ts            chain.ts             format.ts
tools/tf-types-ts/package.json                                                     (+ @noble/ed25519, @noble/hashes)
tools/tf-types-ts/tests/
  signature.test.ts    chain.test.ts        format.test.ts

tools/tf-proof/
  package.json         tsconfig.json
  src/
    cli.ts             keygen.ts            inspect.ts           verify.ts        sign.ts
  tests/
    cli.test.ts

schemas/
  proof-log.schema.json                                                             (+ fixtures)

conformance/
  signature-vectors.yaml  chain-vectors.yaml  framing-vectors.yaml  semantics-vectors.yaml

docs/schemas/proof-log.md                                                           (regenerated)
```

## 9. Phases

1. **Q0** — Rust capability + delegation + revocation + envelope core modules (finishes Phase 0). Shared `conformance/semantics-vectors.yaml` exercised by both runtimes.
2. **Q1** — `crypto` layer on both sides: ed25519 sign/verify, sha256/blake3 hashing. Signature parity vectors pass.
3. **Q2** — `chain` layer: event hashing, chain verification, merkle root. Chain parity vectors pass.
4. **Q3** — `format` layer: `.tflog` reader/writer + `.tfproof` reader/writer. Framing parity vectors pass.
5. **Q4** — `proof-log.schema.json` + fixtures + docs.
6. **Q5** — `tools/tf-proof` CLI with `keygen`, `sign`, `verify`, `inspect`, `derive-pubkey`.
7. **Q6** — CI additions: new test suites, new vectors included in codegen-diff gate.

Each phase ships in one or two commits and leaves the tree green.

## 10. Done criteria

- All tests pass in both runtimes (`bun test`, `cargo test --workspace`).
- Every parity vector is green end-to-end.
- A round-trip demo works: `tf-proof keygen` → `tf-proof sign` → `tf-proof verify` returns 0.
- A Rust-signed `.tfproof` file verifies in TS, and vice versa.
- No `cargo clippy -D warnings` failures, no Bun test warnings.
- CI passes on the full series.

## 11. Risks and open questions

- **`@noble/ed25519` vs `ed25519-dalek` determinism**: both implement RFC 8032 deterministic ed25519 (SHA-512-based nonce), so signatures should be byte-identical for the same key + message. Pinned in signature vectors.
- **Canonical JSON edge cases**: we already match on 14 vectors; the new chain tests add more complex inputs (nested arrays, unicode) and extend the vector file.
- **Merkle tree odd-level handling**: we duplicate the last node (the Bitcoin convention). Documented and pinned in chain vectors.
- **`.tfproof` framing endianness**: u32 big-endian. Documented in §3.3 and tested.
- **Key format**: raw 32-byte bytes for ed25519, wrapped in a tiny JSON header (`{algorithm, key_bytes}`) when written to disk for portability. No PKCS#8, no PEM — we avoid X.509 complexity, since real deployments will supply keys via an OS keystore or HSM we haven't spec'd yet.
