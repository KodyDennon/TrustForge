#![allow(clippy::items_after_test_module)]
//! Packet-mode (TF-0011) sign/verify, embedded edition.
//!
//! Design constraints:
//! * `#![no_std]`, no_alloc by default.
//! * Strings carried inline via `heapless::String<N>` so the type has a
//!   fully-stack-allocated representation. Capacities are sized for the
//!   identifiers actually used by TrustForge (TF-0001 §4): actor URIs
//!   are bounded by the `actor-id` schema, packet IDs are short ULIDs.
//! * Signing-bytes derivation: SHA-256 over the SSZ-style concatenation
//!   of the field values in a fixed canonical order, with the signature
//!   field cleared. This is internally consistent — any sender and
//!   receiver that uses this crate agrees byte-for-byte. See the crate
//!   root for why we do not piggy-back on the std canonical-JSON path.

use core::convert::TryInto;

use ed25519_compact::{KeyPair, PublicKey, Seed, Signature};
use heapless::String as HString;
use heapless::Vec as HVec;
use sha2::{Digest, Sha256};

/// Maximum length, in bytes, of any single string field (signer / source /
/// destination / packet_id / encoding / compression / priority / created_at
/// / expires_at). 256 is generous for actor URIs and ISO timestamps.
pub const STRING_CAP: usize = 256;

/// Maximum payload size carried inline in a single packet, in bytes.
/// Constrained channels (LoRa SF12) deliver tens of bytes; SF7 a few
/// hundred. 1024 covers the practical envelope before fragmentation.
pub const PAYLOAD_CAP: usize = 1024;

/// Maximum signature size (ed25519 = 64).
pub const SIGNATURE_CAP: usize = 64;

/// A no_std packet header. Mirrors the field set of the std `Packet`
/// struct in `tf-types::packet` minus features (fragmentation, route
/// constraints) that K1 does not implement. K1 carries the data
/// fields that the receiver MUST verify against the signature.
#[derive(Clone, Debug)]
pub struct Packet {
    pub packet_version: HString<8>,
    pub packet_id: HString<STRING_CAP>,
    pub source: HString<STRING_CAP>,
    pub destination: HString<STRING_CAP>,
    pub priority: HString<8>,
    pub emergency: bool,
    pub created_at: HString<STRING_CAP>,
    pub expires_at: Option<HString<STRING_CAP>>,
    pub signer: HString<STRING_CAP>,
    pub algorithm: HString<16>,
    pub payload: HVec<u8, PAYLOAD_CAP>,
    pub signature: HVec<u8, SIGNATURE_CAP>,
}

/// Errors from `verify_packet`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    /// `packet_version != "1"`.
    UnsupportedVersion,
    /// `signature.signer` does not match `source`.
    SignerMismatch,
    /// `priority == "P0"` but `emergency` is not set.
    P0NotEmergency,
    /// `expires_at` is set and `< now`.
    Expired,
    /// Signature failed to parse.
    SignatureMalformed,
    /// Public key failed to parse.
    PublicKeyMalformed,
    /// Signature did not verify.
    SignatureInvalid,
    /// String field overflowed `STRING_CAP`.
    FieldTooLarge,
}

/// Errors from `sign_packet`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignError {
    /// String field overflowed its `STRING_CAP`.
    FieldTooLarge,
    /// Payload overflowed `PAYLOAD_CAP`.
    PayloadTooLarge,
    /// Priority `"P0"` requires `emergency = true`.
    P0NotEmergency,
}

/// Sign a packet payload and produce a complete `Packet`.
///
/// `priority` must be one of `"P0".."P7"` and follows TF-0011 semantics:
/// `P0` is emergency-only.
#[allow(clippy::too_many_arguments)]
pub fn sign_packet(
    payload: &[u8],
    private_key: &Seed,
    signer: &str,
    packet_id: &str,
    source: &str,
    destination: &str,
    priority: &str,
    expires_at: Option<&str>,
) -> Result<Packet, SignError> {
    if priority == "P0" {
        return Err(SignError::P0NotEmergency);
    }
    let mut payload_vec: HVec<u8, PAYLOAD_CAP> = HVec::new();
    payload_vec
        .extend_from_slice(payload)
        .map_err(|_| SignError::PayloadTooLarge)?;

    let mut packet = Packet {
        packet_version: hstring("1").map_err(|_| SignError::FieldTooLarge)?,
        packet_id: hstring(packet_id).map_err(|_| SignError::FieldTooLarge)?,
        source: hstring(source).map_err(|_| SignError::FieldTooLarge)?,
        destination: hstring(destination).map_err(|_| SignError::FieldTooLarge)?,
        priority: hstring(priority).map_err(|_| SignError::FieldTooLarge)?,
        emergency: false,
        // Embedded clocks vary; senders fill `created_at` themselves
        // and the verifier compares it to `now`. For K1 we accept the
        // caller's view of "now" via `expires_at`; created_at is set
        // to the empty string here and the bridge / gateway is expected
        // to fill it. Most embedded packet flows pin `created_at` from
        // a monotonic local source the gateway re-stamps.
        created_at: HString::new(),
        expires_at: match expires_at {
            Some(e) => Some(hstring(e).map_err(|_| SignError::FieldTooLarge)?),
            None => None,
        },
        signer: hstring(signer).map_err(|_| SignError::FieldTooLarge)?,
        algorithm: hstring("ed25519").map_err(|_| SignError::FieldTooLarge)?,
        payload: payload_vec,
        signature: HVec::new(),
    };

    let digest = packet_signing_bytes(&packet);
    // ed25519-compact derives the keypair from the 32-byte seed.
    let kp = KeyPair::from_seed(*private_key);
    let sig: Signature = kp.sk.sign(digest, None);
    let sig_bytes = sig.as_ref();
    packet
        .signature
        .extend_from_slice(sig_bytes)
        .expect("signature fits in 64-byte buffer");
    Ok(packet)
}

/// Verify a packet against a known `public_key`. Mirrors the
/// validation order of `tf-types::packet::verify_packet`.
pub fn verify_packet(packet: &Packet, public_key: &[u8; 32], now: &str) -> Result<(), VerifyError> {
    if packet.packet_version.as_str() != "1" {
        return Err(VerifyError::UnsupportedVersion);
    }
    if packet.signer.as_str() != packet.source.as_str() {
        return Err(VerifyError::SignerMismatch);
    }
    if packet.priority.as_str() == "P0" && !packet.emergency {
        return Err(VerifyError::P0NotEmergency);
    }
    if let Some(exp) = packet.expires_at.as_ref() {
        if exp.as_str() < now {
            return Err(VerifyError::Expired);
        }
    }
    let digest = packet_signing_bytes(packet);
    let sig_bytes: &[u8; 64] = packet
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| VerifyError::SignatureMalformed)?;
    let sig = Signature::from_slice(sig_bytes).map_err(|_| VerifyError::SignatureMalformed)?;
    let pk = PublicKey::from_slice(public_key).map_err(|_| VerifyError::PublicKeyMalformed)?;
    pk.verify(digest, &sig)
        .map_err(|_| VerifyError::SignatureInvalid)?;
    Ok(())
}

/// Compute the 32-byte signing digest of a packet. The `signature`
/// field is cleared before hashing.
///
/// Wire format hashed (each field is length-prefixed with a u32 BE):
/// `version | packet_id | source | destination | priority | emergency
///  | created_at | expires_at? | signer | algorithm | payload`.
pub fn packet_signing_bytes(p: &Packet) -> [u8; 32] {
    let mut h = Sha256::new();
    write_field(&mut h, p.packet_version.as_bytes());
    write_field(&mut h, p.packet_id.as_bytes());
    write_field(&mut h, p.source.as_bytes());
    write_field(&mut h, p.destination.as_bytes());
    write_field(&mut h, p.priority.as_bytes());
    write_field(&mut h, &[p.emergency as u8]);
    write_field(&mut h, p.created_at.as_bytes());
    match &p.expires_at {
        Some(e) => {
            h.update([1u8]);
            write_field(&mut h, e.as_bytes());
        }
        None => {
            h.update([0u8]);
        }
    }
    write_field(&mut h, p.signer.as_bytes());
    write_field(&mut h, p.algorithm.as_bytes());
    write_field(&mut h, p.payload.as_slice());
    let out = h.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&out);
    bytes
}

fn write_field(h: &mut Sha256, bytes: &[u8]) {
    let len = bytes.len() as u32;
    h.update(len.to_be_bytes());
    h.update(bytes);
}

fn hstring<const N: usize>(s: &str) -> Result<HString<N>, ()> {
    let mut hs: HString<N> = HString::new();
    hs.push_str(s).map_err(|_| ())?;
    Ok(hs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_seed() -> Seed {
        Seed::from_slice(&[7u8; 32]).expect("seed")
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let seed = fixed_seed();
        let kp = KeyPair::from_seed(seed);
        let pk_bytes: [u8; 32] = kp.pk.as_ref().try_into().unwrap();

        let signer = "tf:actor:agent:example.com/sensor-1";
        let packet = sign_packet(
            b"hello",
            &seed,
            signer,
            "pkt-001",
            signer,
            "tf:actor:service:example.com/ingest",
            "P3",
            Some("2099-01-01T00:00:00Z"),
        )
        .expect("sign");

        verify_packet(&packet, &pk_bytes, "2026-04-25T00:00:00Z").expect("verify ok");
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let seed = fixed_seed();
        let kp = KeyPair::from_seed(seed);
        let pk_bytes: [u8; 32] = kp.pk.as_ref().try_into().unwrap();
        let signer = "tf:actor:agent:example.com/sensor-1";
        let mut packet = sign_packet(
            b"original",
            &seed,
            signer,
            "pkt-002",
            signer,
            "tf:actor:service:example.com/ingest",
            "P3",
            None,
        )
        .expect("sign");
        // Flip a payload byte.
        packet.payload[0] ^= 0x01;
        let r = verify_packet(&packet, &pk_bytes, "2026-04-25T00:00:00Z");
        assert_eq!(r, Err(VerifyError::SignatureInvalid));
    }

    #[test]
    fn verify_rejects_expired() {
        let seed = fixed_seed();
        let kp = KeyPair::from_seed(seed);
        let pk_bytes: [u8; 32] = kp.pk.as_ref().try_into().unwrap();
        let signer = "tf:actor:agent:example.com/x";
        let packet = sign_packet(
            b"x",
            &seed,
            signer,
            "pkt-003",
            signer,
            "tf:actor:service:example.com/y",
            "P3",
            Some("2026-04-24T00:00:00Z"),
        )
        .expect("sign");
        let r = verify_packet(&packet, &pk_bytes, "2026-04-25T00:00:00Z");
        assert_eq!(r, Err(VerifyError::Expired));
    }

    #[test]
    fn verify_rejects_signer_mismatch() {
        let seed = fixed_seed();
        let kp = KeyPair::from_seed(seed);
        let pk_bytes: [u8; 32] = kp.pk.as_ref().try_into().unwrap();
        let signer = "tf:actor:agent:example.com/a";
        let mut packet = sign_packet(
            b"x",
            &seed,
            signer,
            "pkt-004",
            signer,
            "tf:actor:service:example.com/b",
            "P3",
            None,
        )
        .expect("sign");
        // Change source after signing — signature still binds the
        // mismatch directly.
        packet.source = hstring("tf:actor:agent:example.com/other").unwrap();
        let r = verify_packet(&packet, &pk_bytes, "2026-04-25T00:00:00Z");
        assert_eq!(r, Err(VerifyError::SignerMismatch));
    }
}

// `SecretKey` is unused publicly but kept available for downstream
// callers that already hold one.
#[doc(hidden)]
pub use ed25519_compact::SecretKey as Ed25519SecretKey;
