//! `tf-embedded-hal` — TrustForge embedded HAL traits (Phase K8).
//!
//! These traits are the abstraction surface that downstream embedded
//! crates (LoRa drivers, BLE stacks, ATECC608 driver shims, ESP32
//! HW-RNG bindings, etc.) implement. The `tf-core-no-std` crate
//! consumes these traits to do its job — sign, verify, send, receive
//! — without taking a hard dependency on any specific transport or
//! crypto-store backend.
//!
//! All traits are object-safe-friendly and `#![no_std]`-clean. Each
//! has an associated `Error` type so a driver can surface its own
//! transport-specific failure modes without forcing a single global
//! error enum.
//!
//! Mock implementations live in `adapters` for unit tests and for use
//! by host-side simulators.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]
#![warn(rust_2018_idioms)]

pub mod adapters;

use core::fmt::Debug;

/// LoRa-style packet radio. Send/receive are independent so a half-
/// duplex driver implements both methods.
pub trait LoraRadio {
    type Error: Debug;
    /// Transmit `payload` as a single LoRa frame. Blocks until the
    /// frame has been handed to the radio's TX queue.
    fn send(&mut self, payload: &[u8]) -> Result<(), Self::Error>;
    /// Read the next received frame into `buf` and return its size in
    /// bytes. Should block until at least one frame is available, or
    /// return an `Error` on timeout per implementation policy.
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error>;
}

/// BLE advertiser, used by TrustForge's BLE-bridge profile to push
/// short signed packets via advertising payloads.
pub trait BleAdvertiser {
    type Error: Debug;
    fn advertise(&mut self, payload: &[u8]) -> Result<(), Self::Error>;
}

/// NFC reader / receiver — a one-shot tap-to-pair transport for
/// constrained-mode capability handover.
pub trait NfcReader {
    type Error: Debug;
    /// Read a single NDEF / raw record into `buf`; returns its size.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error>;
}

/// A hardware-backed signing key (e.g. ATECC608 / SE050 / Nitrokey).
/// The private material never leaves the device; signing happens via
/// `sign(msg)`.
pub trait SecureElement {
    type Error: Debug;
    /// Sign `msg` and return the 64-byte ed25519 signature.
    fn sign(&mut self, msg: &[u8]) -> Result<[u8; 64], Self::Error>;
    /// Return the 32-byte ed25519 public key bound to this element.
    fn pubkey(&self) -> [u8; 32];
}

/// Hardware random number generator. Used by `tf-core-no-std`
/// callers that need fresh nonces / packet IDs without pulling in
/// `getrandom` (which lacks a default backend on bare metal).
pub trait Entropy {
    type Error: Debug;
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), Self::Error>;
}
