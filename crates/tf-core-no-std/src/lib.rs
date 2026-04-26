//! `tf-core-no-std` — TrustForge embedded core (Phase K1).
//!
//! This crate is the no_std subset of `tf-types`, intended for
//! microcontrollers (Cortex-M4F, RV32IMAC, ESP32-class) that cannot pull
//! in the full std-only protocol surface. It re-implements just the
//! bits a constrained device must do on its own:
//!
//! * `packet`        — sign / verify a packet-mode envelope (TF-0011).
//! * `relay`         — verify a `RelayAuthority` so a relay can refuse
//!                     to forward unauthorised frames offline.
//! * `orl`           — load and consult an Offline Revocation List.
//! * `nonce_cache`   — fixed-capacity replay-protected packet receiver.
//!
//! The crate is `#![no_std]`. With the default `alloc` feature it uses
//! `BTreeMap` / `Vec` / `String`; with `--no-default-features` it falls
//! back to `heapless` containers and is strictly no_alloc, so it links
//! on bare-metal targets without an allocator.
//!
//! Canonicalisation note: the std side (`tf-types::packet`) hashes a
//! canonical-JSON serialisation. Doing that without `alloc` would
//! require a streaming canonical-JSON encoder, which the embedded
//! profile does not need: in packet mode the wire format is CBOR. We
//! therefore hash the CBOR-encoded packet (with the `signature` field
//! zeroed) for the embedded path. The two derivations are not
//! byte-compatible across modes; an embedded device verifies packets
//! signed by another embedded device or by a host that uses this same
//! crate. Cross-mode interop with the std `Packet` is intentionally
//! out of scope for K1 and is the responsibility of a future bridge
//! adaptor.

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]
#![warn(rust_2018_idioms)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod nonce_cache;
pub mod orl;
pub mod packet;
pub mod relay;

/// Compact ed25519 public key (32 bytes).
pub type PublicKeyBytes = [u8; 32];
/// Compact ed25519 secret-key seed (32 bytes).
pub type SecretSeedBytes = [u8; 32];
/// Compact ed25519 signature (64 bytes).
pub type SignatureBytes = [u8; 64];
