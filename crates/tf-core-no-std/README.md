# tf-core-no-std

TrustForge core protocol implemented for #![no_std] environments. Optimized for embedded systems, WebAssembly, and constrained targets.

Part of [TrustForge](https://github.com/KodyDennon/TrustForge) — the open-source trust fabric for
AI-native software, devices, and verifiable action. The Rust crates and
the TypeScript packages (`@trustforge-protocol/*`) are mirrored
reference implementations kept in lockstep by a cross-language
conformance suite.

## Install

```sh
cargo add tf-core-no-std
```

## Overview

`tf-core-no-std` — TrustForge embedded core (Phase K1).

This crate is the no_std subset of `tf-types`, intended for
microcontrollers (Cortex-M4F, RV32IMAC, ESP32-class) that cannot pull
in the full std-only protocol surface. It re-implements just the
bits a constrained device must do on its own:

* `packet`        — sign / verify a packet-mode envelope (TF-0011).
* `relay`         — verify a `RelayAuthority` so a relay can refuse
                    to forward unauthorised frames offline.
* `orl`           — load and consult an Offline Revocation List.
* `nonce_cache`   — fixed-capacity replay-protected packet receiver.

The crate is `#![no_std]`. With the default `alloc` feature it uses
`BTreeMap` / `Vec` / `String`; with `--no-default-features` it falls
back to `heapless` containers and is strictly no_alloc, so it links
on bare-metal targets without an allocator.

Canonicalisation note: the std side (`tf-types::packet`) hashes a
canonical-JSON serialisation. Doing that without `alloc` would
require a streaming canonical-JSON encoder, which the embedded
profile does not need: in packet mode the wire format is CBOR. We
therefore hash the CBOR-encoded packet (with the `signature` field
zeroed) for the embedded path. The two derivations are not
byte-compatible across modes; an embedded device verifies packets
signed by another embedded device or by a host that uses this same
crate. Cross-mode interop with the std `Packet` is intentionally
out of scope for K1 and is the responsibility of a future bridge
adaptor.

## Links

- API docs: [docs.rs/tf-core-no-std](https://docs.rs/tf-core-no-std)
- Source: [crates/tf-core-no-std](https://github.com/KodyDennon/TrustForge/tree/main/crates/tf-core-no-std)
- Specs & conformance vectors: [KodyDennon/TrustForge](https://github.com/KodyDennon/TrustForge)
- Issues: [KodyDennon/TrustForge/issues](https://github.com/KodyDennon/TrustForge/issues)

## Status

Draft — experimental. Apache-2.0.
