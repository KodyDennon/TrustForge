# tf-embedded-hal

TrustForge hardware abstraction layer (HAL) traits. Provides interfaces for LoRa, BLE, NFC, secure elements, and hardware entropy sources.

Part of [TrustForge](https://github.com/KodyDennon/TrustForge) — the open-source trust fabric for
AI-native software, devices, and verifiable action. The Rust crates and
the TypeScript packages (`@trustforge-protocol/*`) are mirrored
reference implementations kept in lockstep by a cross-language
conformance suite.

## Install

```sh
cargo add tf-embedded-hal
```

## Overview

`tf-embedded-hal` — TrustForge embedded HAL traits (Phase K8).

These traits are the abstraction surface that downstream embedded
crates (LoRa drivers, BLE stacks, ATECC608 driver shims, ESP32
HW-RNG bindings, etc.) implement. The `tf-core-no-std` crate
consumes these traits to do its job — sign, verify, send, receive
— without taking a hard dependency on any specific transport or
crypto-store backend.

All traits are object-safe-friendly and `#![no_std]`-clean. Each
has an associated `Error` type so a driver can surface its own
transport-specific failure modes without forcing a single global
error enum.

Mock implementations live in `adapters` for unit tests and for use
by host-side simulators.

## Links

- API docs: [docs.rs/tf-embedded-hal](https://docs.rs/tf-embedded-hal)
- Source: [crates/tf-embedded-hal](https://github.com/KodyDennon/TrustForge/tree/main/crates/tf-embedded-hal)
- Specs & conformance vectors: [KodyDennon/TrustForge](https://github.com/KodyDennon/TrustForge)
- Issues: [KodyDennon/TrustForge/issues](https://github.com/KodyDennon/TrustForge/issues)

## Status

Draft — experimental. Apache-2.0.
