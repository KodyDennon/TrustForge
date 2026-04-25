//! Offline revocation list (TF-0011 §6 / TF-0012 §3) — no_std edition.
//!
//! The std side (`tf-types::constrained::OfflineRevocationListRuntime`)
//! ingests a JSON-or-CBOR document and builds a `HashMap`. On a
//! constrained device we cannot afford either the parser or the heap,
//! so K1 defines a compact length-prefixed binary format the gateway
//! pre-bakes for us. The format is:
//!
//! ```text
//! version: u8                  // = 1
//! issuer_len: u32 BE
//! issuer: bytes
//! issued_at_len: u32 BE        // ISO-8601, lex-orderable
//! issued_at: bytes
//! valid_until_len: u32 BE
//! valid_until: bytes
//! entry_count: u32 BE
//! repeat entry_count times:
//!     kind: u8                 // 1=actor, 2=instance, 3=capability,
//!                              //   4=delegation, 5=key
//!     id_len: u32 BE
//!     id: bytes
//! signature: 64 bytes (ed25519 over SHA-256(version || …entries))
//! ```
//!
//! The signature covers everything before the signature itself — i.e.
//! a SHA-256 of the entire prefix bytes. That makes verification a
//! single-pass streaming check without any allocations.

use core::convert::TryInto;

use ed25519_compact::{PublicKey, Signature};
use sha2::{Digest, Sha256};

#[cfg(not(feature = "alloc"))]
use heapless::FnvIndexMap;
#[cfg(not(feature = "alloc"))]
use heapless::String as HString;

#[cfg(feature = "alloc")]
use alloc::collections::BTreeMap;
#[cfg(feature = "alloc")]
use alloc::string::String;

const ORL_VERSION: u8 = 1;
const SIG_LEN: usize = 64;

/// Capacity of the no_alloc map. 256 entries is sufficient for an
/// edge-relay's local cache (TF-0012 §3 sizing guidance).
pub const NO_ALLOC_CAPACITY: usize = 256;
/// Maximum length of `kind:id` index keys in the no_alloc map.
pub const NO_ALLOC_KEY_CAP: usize = 128;

/// Mirrors `tf-types::generated::offline_revocation_list::RevokedEntry_Kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RevokedKind {
    Actor,
    Instance,
    Capability,
    Delegation,
    Key,
}

impl RevokedKind {
    fn from_u8(b: u8) -> Option<Self> {
        match b {
            1 => Some(RevokedKind::Actor),
            2 => Some(RevokedKind::Instance),
            3 => Some(RevokedKind::Capability),
            4 => Some(RevokedKind::Delegation),
            5 => Some(RevokedKind::Key),
            _ => None,
        }
    }
    pub fn to_u8(self) -> u8 {
        match self {
            RevokedKind::Actor => 1,
            RevokedKind::Instance => 2,
            RevokedKind::Capability => 3,
            RevokedKind::Delegation => 4,
            RevokedKind::Key => 5,
        }
    }
    fn as_str(self) -> &'static str {
        match self {
            RevokedKind::Actor => "actor",
            RevokedKind::Instance => "instance",
            RevokedKind::Capability => "capability",
            RevokedKind::Delegation => "delegation",
            RevokedKind::Key => "key",
        }
    }
}

/// One revoked entry retained in the runtime index.
#[derive(Clone, Debug)]
pub struct RevokedEntry {
    pub kind: RevokedKind,
}

/// Errors from `OfflineRevocationListChecker::new`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrlError {
    /// `version` byte is not 1.
    UnsupportedVersion,
    /// Buffer ended before all expected bytes were read.
    Truncated,
    /// `valid_until` < `now` (lexical compare on ISO-8601).
    Expired,
    /// `issued_at` > `now`.
    FutureDated,
    /// Length prefix exceeded the remaining buffer.
    BadLength,
    /// `kind` byte was not in `1..=5`.
    BadKind,
    /// Signature failed to verify.
    BadSignature,
    /// Public key failed to parse.
    BadPublicKey,
    /// No-alloc capacity overflow.
    CapacityExceeded,
    /// Index key (kind:id) exceeded the no_alloc cap.
    KeyTooLarge,
}

/// The verified ORL runtime. Internally backed by either a heapless
/// `FnvIndexMap` (no_alloc) or a `BTreeMap` (with `alloc`).
#[derive(Debug)]
pub struct OfflineRevocationListChecker {
    #[cfg(feature = "alloc")]
    index: BTreeMap<String, RevokedEntry>,
    #[cfg(not(feature = "alloc"))]
    index: FnvIndexMap<HString<NO_ALLOC_KEY_CAP>, RevokedEntry, NO_ALLOC_CAPACITY>,
}

impl OfflineRevocationListChecker {
    /// Parse, signature-verify, and index an ORL byte buffer.
    pub fn new(list_bytes: &[u8], issuer_pub: &[u8; 32], now: &str) -> Result<Self, OrlError> {
        let mut cur = Cursor::new(list_bytes);
        if cur.read_u8()? != ORL_VERSION {
            return Err(OrlError::UnsupportedVersion);
        }
        let _issuer = cur.read_lp()?;
        let issued_at = cur.read_lp()?;
        let valid_until = cur.read_lp()?;
        if !str_le(valid_until, now.as_bytes()).inverted() {
            // valid_until < now → expired.
            return Err(OrlError::Expired);
        }
        if str_lt(now.as_bytes(), issued_at) {
            return Err(OrlError::FutureDated);
        }
        let entry_count = cur.read_u32()? as usize;
        let entries_start = cur.pos;

        // Slot 1: collect into the index.
        #[cfg(feature = "alloc")]
        let mut index: BTreeMap<String, RevokedEntry> = BTreeMap::new();
        #[cfg(not(feature = "alloc"))]
        let mut index: FnvIndexMap<HString<NO_ALLOC_KEY_CAP>, RevokedEntry, NO_ALLOC_CAPACITY> =
            FnvIndexMap::new();

        for _ in 0..entry_count {
            let kind_byte = cur.read_u8()?;
            let kind = RevokedKind::from_u8(kind_byte).ok_or(OrlError::BadKind)?;
            let id = cur.read_lp()?;
            let key = make_key(kind, id)?;
            let entry = RevokedEntry { kind };
            #[cfg(feature = "alloc")]
            {
                index.insert(key, entry);
            }
            #[cfg(not(feature = "alloc"))]
            {
                if index.insert(key, entry).is_err() {
                    return Err(OrlError::CapacityExceeded);
                }
            }
        }
        let body_end = cur.pos;
        // Signature follows; must be exactly SIG_LEN bytes.
        if list_bytes.len() != body_end + SIG_LEN {
            return Err(OrlError::Truncated);
        }
        let sig_bytes: &[u8; 64] = list_bytes[body_end..]
            .try_into()
            .map_err(|_| OrlError::Truncated)?;

        // Hash the prefix (everything up to the signature).
        let mut h = Sha256::new();
        h.update(&list_bytes[..body_end]);
        let digest = h.finalize();
        let mut digest_bytes = [0u8; 32];
        digest_bytes.copy_from_slice(&digest);

        let sig = Signature::from_slice(sig_bytes).map_err(|_| OrlError::BadSignature)?;
        let pk = PublicKey::from_slice(issuer_pub).map_err(|_| OrlError::BadPublicKey)?;
        pk.verify(digest_bytes, &sig).map_err(|_| OrlError::BadSignature)?;

        // Sanity: re-hash should match prefix bytes; consume `entries_start`
        // to avoid the unused-binding lint while keeping the variable in
        // case future callers want offset-into-buffer diagnostics.
        let _ = entries_start;

        Ok(OfflineRevocationListChecker { index })
    }

    /// `true` if `(kind, id)` appears in the list.
    pub fn is_revoked(&self, kind: RevokedKind, id: &str) -> bool {
        let key = match make_key(kind, id.as_bytes()) {
            Ok(k) => k,
            Err(_) => return false,
        };
        #[cfg(feature = "alloc")]
        {
            self.index.contains_key(&key)
        }
        #[cfg(not(feature = "alloc"))]
        {
            self.index.contains_key(&key)
        }
    }

    /// Number of revocations in the index.
    pub fn len(&self) -> usize {
        self.index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }
}

/// Build the `kind:id` key in the format used by both index variants.
#[cfg(feature = "alloc")]
fn make_key(kind: RevokedKind, id: &[u8]) -> Result<String, OrlError> {
    let mut s = String::with_capacity(kind.as_str().len() + 1 + id.len());
    s.push_str(kind.as_str());
    s.push(':');
    s.push_str(core::str::from_utf8(id).map_err(|_| OrlError::KeyTooLarge)?);
    Ok(s)
}

#[cfg(not(feature = "alloc"))]
fn make_key(kind: RevokedKind, id: &[u8]) -> Result<HString<NO_ALLOC_KEY_CAP>, OrlError> {
    let id_str = core::str::from_utf8(id).map_err(|_| OrlError::KeyTooLarge)?;
    let mut s: HString<NO_ALLOC_KEY_CAP> = HString::new();
    s.push_str(kind.as_str()).map_err(|_| OrlError::KeyTooLarge)?;
    s.push(':').map_err(|_| OrlError::KeyTooLarge)?;
    s.push_str(id_str).map_err(|_| OrlError::KeyTooLarge)?;
    Ok(s)
}

/* ---------------------------- byte cursor ---------------------------- */

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }
    fn read_u8(&mut self) -> Result<u8, OrlError> {
        let b = *self.buf.get(self.pos).ok_or(OrlError::Truncated)?;
        self.pos += 1;
        Ok(b)
    }
    fn read_u32(&mut self) -> Result<u32, OrlError> {
        if self.pos + 4 > self.buf.len() {
            return Err(OrlError::Truncated);
        }
        let bytes: [u8; 4] = self.buf[self.pos..self.pos + 4]
            .try_into()
            .map_err(|_| OrlError::Truncated)?;
        self.pos += 4;
        Ok(u32::from_be_bytes(bytes))
    }
    fn read_lp(&mut self) -> Result<&'a [u8], OrlError> {
        let len = self.read_u32()? as usize;
        if self.pos + len > self.buf.len() {
            return Err(OrlError::BadLength);
        }
        let out = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        Ok(out)
    }
}

/* ----------------------------- helpers ------------------------------- */

#[derive(Clone, Copy)]
struct CmpResult(bool);
impl CmpResult {
    fn inverted(self) -> bool {
        !self.0
    }
}

/// `a <= b` (byte-lexicographic). Equivalent to ISO-8601 lex compare.
fn str_le(a: &[u8], b: &[u8]) -> CmpResult {
    CmpResult(a <= b)
}
fn str_lt(a: &[u8], b: &[u8]) -> bool {
    a < b
}

/* ------------------------------- tests ------------------------------- */

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_compact::{KeyPair, Seed};

    /// Build an ORL byte buffer signed with the given seed.
    fn build_orl(
        seed: &Seed,
        issuer: &str,
        issued_at: &str,
        valid_until: &str,
        entries: &[(RevokedKind, &str)],
    ) -> heapless::Vec<u8, 4096> {
        let mut buf: heapless::Vec<u8, 4096> = heapless::Vec::new();
        buf.push(ORL_VERSION).unwrap();
        write_lp(&mut buf, issuer.as_bytes());
        write_lp(&mut buf, issued_at.as_bytes());
        write_lp(&mut buf, valid_until.as_bytes());
        let count = entries.len() as u32;
        buf.extend_from_slice(&count.to_be_bytes()).unwrap();
        for (k, id) in entries {
            buf.push(k.to_u8()).unwrap();
            write_lp(&mut buf, id.as_bytes());
        }
        // Sign the prefix.
        let mut h = Sha256::new();
        h.update(&buf);
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&h.finalize());
        let kp = KeyPair::from_seed(*seed);
        let sig = kp.sk.sign(digest, None);
        buf.extend_from_slice(sig.as_ref()).unwrap();
        buf
    }

    fn write_lp(buf: &mut heapless::Vec<u8, 4096>, data: &[u8]) {
        let len = data.len() as u32;
        buf.extend_from_slice(&len.to_be_bytes()).unwrap();
        buf.extend_from_slice(data).unwrap();
    }

    #[test]
    fn load_and_lookup() {
        let seed = Seed::from_slice(&[9u8; 32]).unwrap();
        let kp = KeyPair::from_seed(seed);
        let pk: [u8; 32] = kp.pk.as_ref().try_into().unwrap();
        let bytes = build_orl(
            &seed,
            "tf:actor:authority:example.com/root",
            "2026-01-01T00:00:00Z",
            "2099-01-01T00:00:00Z",
            &[
                (RevokedKind::Key, "tf:key:1234"),
                (RevokedKind::Actor, "tf:actor:agent:example.com/bad"),
            ],
        );
        let orl = OfflineRevocationListChecker::new(&bytes, &pk, "2026-04-25T00:00:00Z")
            .expect("load");
        assert_eq!(orl.len(), 2);
        assert!(orl.is_revoked(RevokedKind::Key, "tf:key:1234"));
        assert!(orl.is_revoked(RevokedKind::Actor, "tf:actor:agent:example.com/bad"));
        assert!(!orl.is_revoked(RevokedKind::Capability, "tf:cap:other"));
    }

    #[test]
    fn rejects_expired() {
        let seed = Seed::from_slice(&[9u8; 32]).unwrap();
        let kp = KeyPair::from_seed(seed);
        let pk: [u8; 32] = kp.pk.as_ref().try_into().unwrap();
        let bytes = build_orl(
            &seed,
            "tf:actor:authority:example.com/root",
            "2026-01-01T00:00:00Z",
            "2026-04-01T00:00:00Z",
            &[],
        );
        let r = OfflineRevocationListChecker::new(&bytes, &pk, "2026-04-25T00:00:00Z");
        assert_eq!(r.err(), Some(OrlError::Expired));
    }

    #[test]
    fn rejects_bad_signature() {
        let seed = Seed::from_slice(&[9u8; 32]).unwrap();
        let other = Seed::from_slice(&[2u8; 32]).unwrap();
        let other_kp = KeyPair::from_seed(other);
        let other_pk: [u8; 32] = other_kp.pk.as_ref().try_into().unwrap();
        let bytes = build_orl(
            &seed,
            "tf:actor:authority:example.com/root",
            "2026-01-01T00:00:00Z",
            "2099-01-01T00:00:00Z",
            &[(RevokedKind::Actor, "tf:actor:agent:example.com/bad")],
        );
        let r = OfflineRevocationListChecker::new(&bytes, &other_pk, "2026-04-25T00:00:00Z");
        assert_eq!(r.err(), Some(OrlError::BadSignature));
    }
}
