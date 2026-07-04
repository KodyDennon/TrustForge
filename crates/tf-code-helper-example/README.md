# tf-code-helper-example

TrustForge developer example. Demonstrates how to consume and compile the generated ProofRPC output for downstream applications.

Part of [TrustForge](https://github.com/KodyDennon/TrustForge) — the open-source trust fabric for
AI-native software, devices, and verifiable action. The Rust crates and
the TypeScript packages (`@trustforge-protocol/*`) are mirrored
reference implementations kept in lockstep by a cross-language
conformance suite.

## Install

```sh
cargo add tf-code-helper-example
```

## Overview

Downstream crate that compiles the RPC codegen output against the real
tf-types public API.

This exists so the `tf-schema codegen --target rpc-rust` output is not
just a dead file in the repo: every `cargo check --workspace` compiles
the generated bindings, and the codegen-diff gate in CI fails if
regeneration would change them.

## Links

- API docs: [docs.rs/tf-code-helper-example](https://docs.rs/tf-code-helper-example)
- Source: [crates/tf-code-helper-example](https://github.com/KodyDennon/TrustForge/tree/main/crates/tf-code-helper-example)
- Specs & conformance vectors: [KodyDennon/TrustForge](https://github.com/KodyDennon/TrustForge)
- Issues: [KodyDennon/TrustForge/issues](https://github.com/KodyDennon/TrustForge/issues)

## Status

Draft — experimental. Apache-2.0.
