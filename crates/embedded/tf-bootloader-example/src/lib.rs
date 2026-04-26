//! TrustForge bootloader verifier — verify-then-boot reference.
//!
//! This crate is exposed as both a binary (the actual bootloader you
//! flash to address 0x08000000) and a library (so unit tests can drive
//! the verifier on the host).
//!
//! The verification pattern is:
//!
//!   1. The first-stage bootloader pins a 32-byte ed25519 **boot key**
//!      in its own program memory. In production this key is provisioned
//!      at manufacturing into a write-once flash region (option bytes,
//!      RDP-protected sector, factory-locked OTP).
//!
//!   2. A signed bundle lives in the application slot. The bundle
//!      layout is:
//!
//!        Offset  Size  Field
//!        ------  ----  ---------------------------------------
//!        0       4     magic "TFB1"  (0x54 0x46 0x42 0x31)
//!        4       4     bundle_len (u32 LE) — total bytes incl. signature
//!        8       4     image_len  (u32 LE) — bytes to verify (= bundle_len - 16 - 64)
//!        12      4     reserved (zero, future flags)
//!        16      N     image bytes (vector table + code; 16-byte aligned)
//!        16+N    64    ed25519 signature over bytes 0..(16+N)
//!
//!      The image proper starts at offset 16 from the bundle base, so
//!      the application's reset vector (the second 4-byte word of its
//!      vector table) lives at `app_base + 16 + 4`.
//!
//!   3. On boot the bootloader:
//!        a. reads the magic and validates it,
//!        b. checks bundle_len against the slot size,
//!        c. computes SHA-256 over `bundle[0..16+image_len]`,
//!        d. ed25519-verifies the trailing 64-byte signature against
//!           the pinned boot key,
//!        e. if any step fails, falls back to a recovery state (LED
//!           blink, USB DFU, etc.); otherwise jumps to the application's
//!           reset handler with a clean MSP/PSP and SCB->VTOR set to
//!           the application's base.
//!
//! The verification body is the same `ed25519-compact` + `sha2` path
//! that `tf-core-no-std::packet::verify_packet` uses, so the bundle
//! signing tool can be implemented with the same primitives. See
//! `tools/native/tf-bundle-sign/` for the host-side signer (out of
//! scope for K9 — referenced for reproducibility).

#![cfg_attr(not(test), no_std)]

use ed25519_compact::{PublicKey, Signature};
use sha2::{Digest, Sha256};

/// Magic that prefixes a TrustForge bundle. ASCII "TFB1".
pub const BUNDLE_MAGIC: [u8; 4] = *b"TFB1";

/// Fixed 16-byte header before the image bytes.
pub const HEADER_LEN: usize = 16;

/// Length of the trailing ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;

/// Errors returned by `verify_bundle`. The bootloader translates these
/// into recovery-state codes; production firmware never proceeds to
/// `boot_application` if anything but `Ok(())` is returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootVerifyError {
    /// First 4 bytes are not "TFB1".
    BadMagic,
    /// Header claims a length that is too short (`< HEADER_LEN + SIGNATURE_LEN`).
    HeaderTooShort,
    /// Header claims a length that exceeds the supplied slot.
    SlotOverflow,
    /// The image-length field is inconsistent with `bundle_len`.
    LengthMismatch,
    /// SHA-256 + ed25519 verify failed.
    BadSignature,
    /// Pinned key didn't parse (programmer error — fixed at compile time).
    BadKey,
    /// Pinned signature blob didn't parse (corrupt slot).
    BadSignatureFormat,
}

/// Verify a TrustForge boot bundle stored in `slot`.
///
/// `slot` is a slice over the application's flash slot. Only the
/// first `bundle_len` bytes are read; the slot may be larger (excess
/// bytes are ignored).
///
/// On success, returns `Ok((image_offset, image_len))` — the offset
/// and size of the verified image bytes within `slot`. The bootloader
/// uses these to compute the application's reset vector before
/// jumping.
pub fn verify_bundle(
    slot: &[u8],
    pinned_pubkey: &[u8; 32],
) -> Result<(usize, usize), BootVerifyError> {
    if slot.len() < HEADER_LEN + SIGNATURE_LEN {
        return Err(BootVerifyError::HeaderTooShort);
    }
    if slot[..4] != BUNDLE_MAGIC {
        return Err(BootVerifyError::BadMagic);
    }
    let bundle_len = u32::from_le_bytes([slot[4], slot[5], slot[6], slot[7]]) as usize;
    let image_len  = u32::from_le_bytes([slot[8], slot[9], slot[10], slot[11]]) as usize;
    if bundle_len < HEADER_LEN + SIGNATURE_LEN {
        return Err(BootVerifyError::HeaderTooShort);
    }
    if bundle_len > slot.len() {
        return Err(BootVerifyError::SlotOverflow);
    }
    if HEADER_LEN + image_len + SIGNATURE_LEN != bundle_len {
        return Err(BootVerifyError::LengthMismatch);
    }

    let signed_bytes = &slot[..HEADER_LEN + image_len];
    let sig_bytes    = &slot[HEADER_LEN + image_len..bundle_len];

    let mut h = Sha256::new();
    h.update(signed_bytes);
    let digest = h.finalize();

    let pk  = PublicKey::from_slice(pinned_pubkey)
        .map_err(|_| BootVerifyError::BadKey)?;
    let sig = Signature::from_slice(sig_bytes)
        .map_err(|_| BootVerifyError::BadSignatureFormat)?;
    pk.verify(digest.as_slice(), &sig)
        .map_err(|_| BootVerifyError::BadSignature)?;

    Ok((HEADER_LEN, image_len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_compact::{KeyPair, Seed};

    fn build_bundle(image: &[u8], seed_bytes: [u8; 32]) -> ([u8; 32], std::vec::Vec<u8>) {
        let seed = Seed::from_slice(&seed_bytes).unwrap();
        let kp = KeyPair::from_seed(seed);
        let pk: [u8; 32] = kp.pk.as_ref().try_into().unwrap();
        let bundle_len = HEADER_LEN + image.len() + SIGNATURE_LEN;
        let mut bundle = std::vec::Vec::with_capacity(bundle_len);
        bundle.extend_from_slice(&BUNDLE_MAGIC);
        bundle.extend_from_slice(&(bundle_len as u32).to_le_bytes());
        bundle.extend_from_slice(&(image.len() as u32).to_le_bytes());
        bundle.extend_from_slice(&[0u8; 4]);
        bundle.extend_from_slice(image);
        let mut h = Sha256::new();
        h.update(&bundle[..HEADER_LEN + image.len()]);
        let digest = h.finalize();
        let sig = kp.sk.sign(digest.as_slice(), None);
        bundle.extend_from_slice(sig.as_ref());
        (pk, bundle)
    }

    #[test]
    fn verifies_a_well_formed_bundle() {
        let (pk, bundle) = build_bundle(b"hello-world-image-123", [9u8; 32]);
        let (off, len) = verify_bundle(&bundle, &pk).unwrap();
        assert_eq!(off, HEADER_LEN);
        assert_eq!(len, b"hello-world-image-123".len());
    }

    #[test]
    fn rejects_bad_magic() {
        let (pk, mut bundle) = build_bundle(b"x", [9u8; 32]);
        bundle[0] = b'X';
        assert_eq!(verify_bundle(&bundle, &pk), Err(BootVerifyError::BadMagic));
    }

    #[test]
    fn rejects_tampered_image() {
        let (pk, mut bundle) = build_bundle(b"original-image", [9u8; 32]);
        bundle[HEADER_LEN] ^= 0x01;
        assert_eq!(verify_bundle(&bundle, &pk), Err(BootVerifyError::BadSignature));
    }

    #[test]
    fn rejects_wrong_key() {
        let (_pk_correct, bundle) = build_bundle(b"image", [9u8; 32]);
        // Use a different keypair's public key.
        let kp_other = KeyPair::from_seed(Seed::from_slice(&[1u8; 32]).unwrap());
        let pk_other: [u8; 32] = kp_other.pk.as_ref().try_into().unwrap();
        assert_eq!(verify_bundle(&bundle, &pk_other), Err(BootVerifyError::BadSignature));
    }
}
