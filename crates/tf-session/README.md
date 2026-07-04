# tf-session

TrustForge session carrier driver. Implements the secure handshake, AEAD framing, and perfect forward secrecy for network sessions.

Part of [TrustForge](https://github.com/KodyDennon/TrustForge) — the open-source trust fabric for
AI-native software, devices, and verifiable action. The Rust crates and
the TypeScript packages (`@trustforge-protocol/*`) are mirrored
reference implementations kept in lockstep by a cross-language
conformance suite.

## Install

```sh
cargo add tf-session
```

## Overview

The carrier driver for TrustForge network sessions over TCP or any
Tokio duplex stream: mutual-authentication handshake, AEAD frame
codec, key ratcheting for perfect forward secrecy, and an
`RpcTransport` binding so ProofRPC calls ride authenticated sessions.
Mirrors the TypeScript driver in `tools/tf-session`.

## Links

- API docs: [docs.rs/tf-session](https://docs.rs/tf-session)
- Source: [crates/tf-session](https://github.com/KodyDennon/TrustForge/tree/main/crates/tf-session)
- Specs & conformance vectors: [KodyDennon/TrustForge](https://github.com/KodyDennon/TrustForge)
- Issues: [KodyDennon/TrustForge/issues](https://github.com/KodyDennon/TrustForge/issues)

## Status

Draft — experimental. Apache-2.0.
