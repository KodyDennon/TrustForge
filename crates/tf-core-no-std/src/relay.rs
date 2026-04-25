//! Relay-authority verification (TF-0011 §5), no_std edition.
//!
//! A `RelayAuthority` is a signed grant that lets a relay carry frames
//! for a particular trust domain and packet kinds. Forwarding authority
//! is strictly separate from action authority — even an authorised
//! relay sees only ciphertext.
//!
//! The constrained variant carries the same field set as the std
//! `tf-types::relay::RelayAuthority` but uses fixed-cap heapless
//! containers. The signing-bytes derivation uses the same SSZ-style
//! length-prefixed concatenation as `packet::packet_signing_bytes`.

use core::convert::TryInto;

use ed25519_compact::{PublicKey, Signature};
use heapless::String as HString;
use heapless::Vec as HVec;
use sha2::{Digest, Sha256};

/// Capacity for ID and timestamp string fields.
pub const STRING_CAP: usize = 256;
/// Maximum number of `kinds` strings we can hold. TF-0011 lists ~6 today.
pub const KINDS_CAP: usize = 16;

/// Compact ed25519 signature envelope.
#[derive(Clone, Debug)]
pub struct SignatureEnvelope {
    pub algorithm: HString<16>,
    pub signer: HString<STRING_CAP>,
    pub signature: HVec<u8, 64>,
}

/// A relay authority grant. Mirrors `tf-types::relay::RelayAuthority`.
#[derive(Clone, Debug)]
pub struct RelayAuthority {
    pub relay_authority_version: HString<8>,
    pub relay: HString<STRING_CAP>,
    pub trust_domain: HString<STRING_CAP>,
    pub kinds: HVec<HString<32>, KINDS_CAP>,
    pub max_hop_count: Option<u32>,
    pub rate_limit_per_minute: Option<u32>,
    pub valid_from: HString<STRING_CAP>,
    pub valid_until: Option<HString<STRING_CAP>>,
    pub issuer: HString<STRING_CAP>,
    pub signature: SignatureEnvelope,
}

/// Compute the 32-byte digest used to bind the relay-authority
/// signature. The signature envelope is cleared before hashing.
pub fn relay_authority_signing_bytes(a: &RelayAuthority) -> [u8; 32] {
    let mut h = Sha256::new();
    write_field(&mut h, a.relay_authority_version.as_bytes());
    write_field(&mut h, a.relay.as_bytes());
    write_field(&mut h, a.trust_domain.as_bytes());
    let count = a.kinds.len() as u32;
    h.update(count.to_be_bytes());
    for k in a.kinds.iter() {
        write_field(&mut h, k.as_bytes());
    }
    write_optional_u32(&mut h, a.max_hop_count);
    write_optional_u32(&mut h, a.rate_limit_per_minute);
    write_field(&mut h, a.valid_from.as_bytes());
    write_optional_str(&mut h, a.valid_until.as_ref().map(|s| s.as_str()));
    write_field(&mut h, a.issuer.as_bytes());
    let out = h.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&out);
    bytes
}

/// Verify a relay authority against the issuer's known public key.
/// Returns `true` only on a clean, well-formed verify; any structural
/// or cryptographic problem yields `false`. Use the std side if you
/// need the textual reason.
pub fn verify_relay_authority(authority: &RelayAuthority, issuer_pub: &[u8; 32]) -> bool {
    if authority.relay_authority_version.as_str() != "1" {
        return false;
    }
    if authority.signature.algorithm.as_str() != "ed25519" {
        return false;
    }
    if authority.signature.signer.as_str() != authority.issuer.as_str() {
        return false;
    }
    let digest = relay_authority_signing_bytes(authority);
    let sig_bytes: &[u8; 64] = match authority.signature.signature.as_slice().try_into() {
        Ok(s) => s,
        Err(_) => return false,
    };
    let sig = match Signature::from_slice(sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let pk = match PublicKey::from_slice(issuer_pub) {
        Ok(p) => p,
        Err(_) => return false,
    };
    pk.verify(digest, &sig).is_ok()
}

fn write_field(h: &mut Sha256, bytes: &[u8]) {
    let len = bytes.len() as u32;
    h.update(len.to_be_bytes());
    h.update(bytes);
}

fn write_optional_u32(h: &mut Sha256, v: Option<u32>) {
    match v {
        Some(n) => {
            h.update([1u8]);
            h.update(n.to_be_bytes());
        }
        None => h.update([0u8]),
    }
}

fn write_optional_str(h: &mut Sha256, v: Option<&str>) {
    match v {
        Some(s) => {
            h.update([1u8]);
            write_field(h, s.as_bytes());
        }
        None => {
            h.update([0u8]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_compact::{KeyPair, Seed};

    fn hstring<const N: usize>(s: &str) -> HString<N> {
        let mut hs = HString::new();
        hs.push_str(s).unwrap();
        hs
    }

    fn build_and_sign() -> (RelayAuthority, [u8; 32]) {
        let seed = Seed::from_slice(&[3u8; 32]).unwrap();
        let kp = KeyPair::from_seed(seed);
        let pk_bytes: [u8; 32] = kp.pk.as_ref().try_into().unwrap();

        let mut kinds: HVec<HString<32>, KINDS_CAP> = HVec::new();
        kinds.push(hstring("packet")).unwrap();
        kinds.push(hstring("relay-frame")).unwrap();

        let mut auth = RelayAuthority {
            relay_authority_version: hstring("1"),
            relay: hstring("tf:actor:relay:example.com/edge-01"),
            trust_domain: hstring("example.com"),
            kinds,
            max_hop_count: Some(4),
            rate_limit_per_minute: Some(60),
            valid_from: hstring("2026-01-01T00:00:00Z"),
            valid_until: Some(hstring("2099-01-01T00:00:00Z")),
            issuer: hstring("tf:actor:authority:example.com/root"),
            signature: SignatureEnvelope {
                algorithm: hstring("ed25519"),
                signer: hstring("tf:actor:authority:example.com/root"),
                signature: HVec::new(),
            },
        };
        let digest = relay_authority_signing_bytes(&auth);
        let sig = kp.sk.sign(digest, None);
        auth.signature.signature.extend_from_slice(sig.as_ref()).unwrap();
        (auth, pk_bytes)
    }

    #[test]
    fn verify_relay_authority_happy_path() {
        let (auth, pk) = build_and_sign();
        assert!(verify_relay_authority(&auth, &pk));
    }

    #[test]
    fn verify_relay_authority_rejects_tamper() {
        let (mut auth, pk) = build_and_sign();
        auth.relay = hstring("tf:actor:relay:evil.example/imposter");
        assert!(!verify_relay_authority(&auth, &pk));
    }

    #[test]
    fn verify_relay_authority_rejects_signer_mismatch() {
        let (mut auth, pk) = build_and_sign();
        auth.signature.signer = hstring("tf:actor:other:example.com/a");
        assert!(!verify_relay_authority(&auth, &pk));
    }
}
