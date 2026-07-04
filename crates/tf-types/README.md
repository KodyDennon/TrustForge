# tf-types

Core semantic types, traits, and schemas powering the TrustForge protocol.

Part of [TrustForge](https://github.com/KodyDennon/TrustForge) — the open-source trust fabric for
AI-native software, devices, and verifiable action. The Rust crates and
the TypeScript packages (`@trustforge-protocol/*`) are mirrored
reference implementations kept in lockstep by a cross-language
conformance suite.

## Install

```sh
cargo add tf-types
```

## Overview

TrustForge type bindings and semantic core. Generated wire types live
under `generated/`; hand-written semantic helpers live as sibling
modules:

- **Identity & authority** — actor / instance IDs, trust domains,
  capabilities and negative capabilities, delegation chains,
  revocation, quorum, approval ceremonies.
- **Wire formats** — `.tfpkt` / `.tfbundle` binary containers,
  packets, envelopes, proof events, session primitives.
- **In-house codec layer** (mirrored 1:1 with the TS package, gated by
  cross-language conformance vectors): canonical JSON (`canonical`),
  deterministic CBOR (`cbor`), TF-YAML strict subset (`yaml`), compact
  JWS/JWT (`jws`), base64 (`encoding`), and the capability glob
  language (`glob`).
- **Bridges** — WebAuthn, SPIFFE, OAuth/GNAP, MCP/A2A, TLS, DID,
  Matrix, service-mesh compatibility projections.
- **Policy** — the native policy engine, agent guard, and manifest
  loaders for `.tf/` (agent contract, threat model, policy).

Cryptographic primitives are never implemented here — signature, AEAD,
hash, and KDF math delegates to reviewed crates (`ed25519-dalek`,
`p256`/`p384`, `rsa`, `chacha20poly1305`, `sha2`, `blake3`, `argon2`).

## Links

- API docs: [docs.rs/tf-types](https://docs.rs/tf-types)
- Source: [crates/tf-types](https://github.com/KodyDennon/TrustForge/tree/main/crates/tf-types)
- Specs & conformance vectors: [KodyDennon/TrustForge](https://github.com/KodyDennon/TrustForge)
- Issues: [KodyDennon/TrustForge/issues](https://github.com/KodyDennon/TrustForge/issues)

## Status

Draft — experimental. Apache-2.0.
