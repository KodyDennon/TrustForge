//! Constrained-mode runtime primitives — Rust mirror of
//! `tools/tf-types-ts/src/core/constrained.ts`.
//!
//! Constrained deployments (LoRa mesh, air-gapped relays, USB-shuttle,
//! intermittent satellites) need anti-replay protection on the
//! receiver, a way to honour offline revocations without phoning home,
//! delivery receipts so packets sent over a one-way bearer can prove
//! they arrived, and proof-of-forwarding receipts so a relay can show
//! it actually carried a packet without seeing its plaintext.

use std::collections::{HashMap, VecDeque};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::canonicalize;
use crate::generated::offline_revocation_list::{
    OfflineRevocationList, OfflineRevocationList_ListVersion, RevokedEntry, RevokedEntry_Kind,
};
use crate::packet::Packet;

/* -------------------------------------------------------------------------- */
/*  PacketReceiver — sliding-window nonce cache                               */
/* -------------------------------------------------------------------------- */

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PacketRejectReason {
    Replay,
    Expired,
    FutureDated,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum PacketReceiverDecision {
    Accept,
    Reject { reason: PacketRejectReason },
}

#[derive(Debug)]
pub struct PacketReceiver {
    /// `(packet_id, expires_at)` pairs in insertion order. We push to
    /// the back, evict from the front for LRU semantics.
    seen: VecDeque<(String, String)>,
    /// Set membership for O(1) replay checks. Mirrors `seen`.
    index: HashMap<String, ()>,
    window_size: usize,
}

impl PacketReceiver {
    pub fn new(window_size: Option<usize>) -> Self {
        let window_size = window_size.unwrap_or(4096);
        PacketReceiver {
            seen: VecDeque::with_capacity(window_size),
            index: HashMap::with_capacity(window_size),
            window_size,
        }
    }

    /// Check + record a packet. Pure decision; if you call this twice
    /// with the same packet, the second call returns `Replay`.
    pub fn observe(&mut self, packet: &Packet, now: &str) -> PacketReceiverDecision {
        if let Some(exp) = packet.expires_at.as_deref() {
            if exp < now {
                return PacketReceiverDecision::Reject {
                    reason: PacketRejectReason::Expired,
                };
            }
        }
        if packet.created_at.as_str() > now {
            return PacketReceiverDecision::Reject {
                reason: PacketRejectReason::FutureDated,
            };
        }
        if self.index.contains_key(&packet.packet_id) {
            return PacketReceiverDecision::Reject {
                reason: PacketRejectReason::Replay,
            };
        }
        if self.seen.len() >= self.window_size {
            if let Some((oldest, _)) = self.seen.pop_front() {
                self.index.remove(&oldest);
            }
        }
        self.seen.push_back((
            packet.packet_id.clone(),
            packet.expires_at.clone().unwrap_or_default(),
        ));
        self.index.insert(packet.packet_id.clone(), ());
        PacketReceiverDecision::Accept
    }

    /// Drop entries whose recorded `expires_at` is `< before`. Useful
    /// at start-of-tick on a receiver that wants the window to follow
    /// real time rather than just LRU.
    pub fn expire_older_than(&mut self, before: &str) -> usize {
        let mut removed = 0usize;
        // Walk from the front; entries with non-empty exp older than
        // `before` are dropped. Stop on first entry that should stay
        // — but since we may have unsorted exp values we instead keep
        // a fresh deque of survivors.
        let mut survivors: VecDeque<(String, String)> = VecDeque::with_capacity(self.seen.len());
        let mut new_index: HashMap<String, ()> = HashMap::with_capacity(self.seen.len());
        for entry in self.seen.drain(..) {
            let drop = !entry.1.is_empty() && entry.1.as_str() < before;
            if drop {
                removed += 1;
            } else {
                new_index.insert(entry.0.clone(), ());
                survivors.push_back(entry);
            }
        }
        self.seen = survivors;
        self.index = new_index;
        removed
    }

    pub fn size(&self) -> usize {
        self.seen.len()
    }
}

/* -------------------------------------------------------------------------- */
/*  OfflineRevocationListRuntime — sealed-list verifier                       */
/* -------------------------------------------------------------------------- */

#[derive(Debug, thiserror::Error)]
pub enum OrlError {
    #[error("offline revocation list version unsupported")]
    UnsupportedVersion,
    #[error("offline revocation list expired at {0}")]
    Expired(String),
    #[error("offline revocation list dated in the future: {0}")]
    FutureDated(String),
    #[error("offline revocation list signature did not verify")]
    BadSignature,
    #[error("signature decode: {0}")]
    SignatureDecode(String),
    #[error("verifying key: {0}")]
    VerifyingKey(String),
    #[error("canonicalize: {0}")]
    Canonicalize(String),
}

#[derive(Debug)]
pub struct OfflineRevocationListRuntime {
    list: OfflineRevocationList,
    /// `"<kind>:<id>"` → entry index for O(1) lookup. We collapse to a
    /// string key because `RevokedEntry_Kind` is generated and can't
    /// derive `Hash` without changing the codegen.
    index: HashMap<String, RevokedEntry>,
}

fn revoked_entry_kind_str(k: &RevokedEntry_Kind) -> &'static str {
    match k {
        RevokedEntry_Kind::Actor => "actor",
        RevokedEntry_Kind::Instance => "instance",
        RevokedEntry_Kind::Capability => "capability",
        RevokedEntry_Kind::Delegation => "delegation",
        RevokedEntry_Kind::Key => "key",
    }
}

impl OfflineRevocationListRuntime {
    /// Build the runtime AFTER verifying the issuer signature. Refuses
    /// to construct if the signature does not validate, the list has
    /// expired (`valid_until` < now), or the list version is unknown.
    pub fn load(
        list: OfflineRevocationList,
        issuer_public_key: &[u8; 32],
        now: &str,
    ) -> Result<Self, OrlError> {
        if list.list_version != OfflineRevocationList_ListVersion::V1 {
            return Err(OrlError::UnsupportedVersion);
        }
        if list.valid_until.as_str() < now {
            return Err(OrlError::Expired(list.valid_until.clone()));
        }
        if list.issued_at.as_str() > now {
            return Err(OrlError::FutureDated(list.issued_at.clone()));
        }
        if !verify_offline_revocation_list_signature(&list, issuer_public_key)? {
            return Err(OrlError::BadSignature);
        }
        let mut index: HashMap<String, RevokedEntry> = HashMap::new();
        for e in &list.revoked {
            index.insert(format!("{}:{}", revoked_entry_kind_str(&e.kind), e.id), e.clone());
        }
        Ok(OfflineRevocationListRuntime { list, index })
    }

    /// Was a target revoked by this list?
    pub fn is_revoked(&self, kind: &RevokedEntry_Kind, id: &str) -> Option<&RevokedEntry> {
        self.index
            .get(&format!("{}:{}", revoked_entry_kind_str(kind), id))
    }

    pub fn metadata(&self) -> OrlMetadata<'_> {
        OrlMetadata {
            issuer: &self.list.issuer,
            trust_domain: &self.list.trust_domain,
            issued_at: &self.list.issued_at,
            valid_until: &self.list.valid_until,
        }
    }
}

#[derive(Debug)]
pub struct OrlMetadata<'a> {
    pub issuer: &'a str,
    pub trust_domain: &'a str,
    pub issued_at: &'a str,
    pub valid_until: &'a str,
}

pub fn verify_offline_revocation_list_signature(
    list: &OfflineRevocationList,
    public_key: &[u8; 32],
) -> Result<bool, OrlError> {
    let mut value = serde_json::to_value(list).unwrap_or(serde_json::Value::Null);
    if let serde_json::Value::Object(map) = &mut value {
        map.remove("signature");
    }
    let canonical = canonicalize(&value).map_err(|e| OrlError::Canonicalize(e.to_string()))?;
    let sig_bytes = STANDARD
        .decode(&list.signature.signature)
        .map_err(|e| OrlError::SignatureDecode(e.to_string()))?;
    let sig = match Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    let vk = VerifyingKey::from_bytes(public_key).map_err(|e| OrlError::VerifyingKey(e.to_string()))?;
    Ok(vk.verify(canonical.as_bytes(), &sig).is_ok())
}

pub fn sign_offline_revocation_list(
    mut list: OfflineRevocationList,
    private_key: &[u8; 32],
) -> Result<OfflineRevocationList, OrlError> {
    // Zero out signature before canonicalising.
    list.signature = crate::generated::common::SignatureEnvelope {
        algorithm: list.signature.algorithm.clone(),
        signer: list.signature.signer.clone(),
        signature: String::new(),
        hash_alg: None,
        alt_algorithm: None,
        alt_signature: None,
    };
    let mut value = serde_json::to_value(&list).unwrap_or(serde_json::Value::Null);
    if let serde_json::Value::Object(map) = &mut value {
        map.remove("signature");
    }
    let canonical = canonicalize(&value).map_err(|e| OrlError::Canonicalize(e.to_string()))?;
    let signing = SigningKey::from_bytes(private_key);
    let sig: Signature = signing.sign(canonical.as_bytes());
    list.signature.signature = STANDARD.encode(sig.to_bytes());
    Ok(list)
}

/* -------------------------------------------------------------------------- */
/*  Delivery receipts                                                         */
/* -------------------------------------------------------------------------- */

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeliveryReceipt {
    pub receipt_version: String,
    pub packet_id: String,
    /// `sha256:<hex>` digest of the verified packet payload, so the
    /// receipt is bound to the actual bytes the receiver saw.
    pub packet_hash: String,
    pub receiver: String,
    pub received_at: String,
    pub signature: ReceiptSignature,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiptSignature {
    pub algorithm: String,
    pub signer: String,
    pub signature: String,
}

#[derive(Debug)]
pub struct VerifyResult {
    pub ok: bool,
    pub reason: Option<String>,
}

fn sha256_hashref(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let hex: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
    format!("sha256:{}", hex)
}

pub fn sign_delivery_receipt(
    packet: &Packet,
    receiver: &str,
    received_at: &str,
    private_key: &[u8; 32],
) -> Result<DeliveryReceipt, OrlError> {
    let canonical_packet =
        canonicalize(&serde_json::to_value(packet).unwrap_or(serde_json::Value::Null))
            .map_err(|e| OrlError::Canonicalize(e.to_string()))?;
    let packet_hash = sha256_hashref(canonical_packet.as_bytes());
    let mut draft = DeliveryReceipt {
        receipt_version: "1".into(),
        packet_id: packet.packet_id.clone(),
        packet_hash,
        receiver: receiver.into(),
        received_at: received_at.into(),
        signature: ReceiptSignature {
            algorithm: "ed25519".into(),
            signer: receiver.into(),
            signature: String::new(),
        },
    };
    let mut sig_value =
        serde_json::to_value(&draft).map_err(|e| OrlError::Canonicalize(e.to_string()))?;
    if let serde_json::Value::Object(map) = &mut sig_value {
        map.remove("signature");
    }
    let sig_canonical =
        canonicalize(&sig_value).map_err(|e| OrlError::Canonicalize(e.to_string()))?;
    let signing = SigningKey::from_bytes(private_key);
    let sig: Signature = signing.sign(sig_canonical.as_bytes());
    draft.signature.signature = STANDARD.encode(sig.to_bytes());
    Ok(draft)
}

pub fn verify_delivery_receipt(
    receipt: &DeliveryReceipt,
    packet: &Packet,
    receiver_public_key: &[u8; 32],
) -> VerifyResult {
    if receipt.receipt_version != "1" {
        return reject(format!(
            "receipt_version {} unsupported",
            receipt.receipt_version
        ));
    }
    if receipt.packet_id != packet.packet_id {
        return reject("packet_id mismatch".into());
    }
    let canonical_packet = match canonicalize(&serde_json::to_value(packet).unwrap_or_default()) {
        Ok(c) => c,
        Err(e) => return reject(format!("canonicalize: {}", e)),
    };
    let expected = sha256_hashref(canonical_packet.as_bytes());
    if expected != receipt.packet_hash {
        return reject("packet_hash mismatch".into());
    }
    if receipt.signature.signer != receipt.receiver {
        return reject("receipt signer != receiver".into());
    }
    let mut sig_value = match serde_json::to_value(receipt) {
        Ok(v) => v,
        Err(e) => return reject(format!("serde: {}", e)),
    };
    if let serde_json::Value::Object(map) = &mut sig_value {
        map.remove("signature");
    }
    let sig_canonical = match canonicalize(&sig_value) {
        Ok(c) => c,
        Err(e) => return reject(format!("canonicalize: {}", e)),
    };
    let sig_bytes = match STANDARD.decode(&receipt.signature.signature) {
        Ok(b) => b,
        Err(e) => return reject(format!("signature base64: {}", e)),
    };
    let sig = match Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(e) => return reject(format!("signature parse: {}", e)),
    };
    let vk = match VerifyingKey::from_bytes(receiver_public_key) {
        Ok(v) => v,
        Err(e) => return reject(format!("verifying key: {}", e)),
    };
    if vk.verify(sig_canonical.as_bytes(), &sig).is_err() {
        return reject("receipt signature did not verify".into());
    }
    VerifyResult {
        ok: true,
        reason: None,
    }
}

/* -------------------------------------------------------------------------- */
/*  Proof of forwarding                                                       */
/* -------------------------------------------------------------------------- */

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofOfForwarding {
    pub proof_version: String,
    pub packet_id: String,
    pub packet_hash: String,
    pub relay: String,
    pub forwarded_at: String,
    pub hop_count: u32,
    pub signature: ReceiptSignature,
}

pub fn sign_proof_of_forwarding(
    packet: &Packet,
    relay: &str,
    forwarded_at: &str,
    hop_count: u32,
    private_key: &[u8; 32],
) -> Result<ProofOfForwarding, OrlError> {
    let canonical_packet =
        canonicalize(&serde_json::to_value(packet).unwrap_or(serde_json::Value::Null))
            .map_err(|e| OrlError::Canonicalize(e.to_string()))?;
    let packet_hash = sha256_hashref(canonical_packet.as_bytes());
    let mut draft = ProofOfForwarding {
        proof_version: "1".into(),
        packet_id: packet.packet_id.clone(),
        packet_hash,
        relay: relay.into(),
        forwarded_at: forwarded_at.into(),
        hop_count,
        signature: ReceiptSignature {
            algorithm: "ed25519".into(),
            signer: relay.into(),
            signature: String::new(),
        },
    };
    let mut sig_value =
        serde_json::to_value(&draft).map_err(|e| OrlError::Canonicalize(e.to_string()))?;
    if let serde_json::Value::Object(map) = &mut sig_value {
        map.remove("signature");
    }
    let sig_canonical =
        canonicalize(&sig_value).map_err(|e| OrlError::Canonicalize(e.to_string()))?;
    let signing = SigningKey::from_bytes(private_key);
    let sig: Signature = signing.sign(sig_canonical.as_bytes());
    draft.signature.signature = STANDARD.encode(sig.to_bytes());
    Ok(draft)
}

pub fn verify_proof_of_forwarding(
    proof: &ProofOfForwarding,
    packet: &Packet,
    relay_public_key: &[u8; 32],
) -> VerifyResult {
    if proof.proof_version != "1" {
        return reject(format!("proof_version {} unsupported", proof.proof_version));
    }
    if proof.packet_id != packet.packet_id {
        return reject("packet_id mismatch".into());
    }
    let canonical_packet = match canonicalize(&serde_json::to_value(packet).unwrap_or_default()) {
        Ok(c) => c,
        Err(e) => return reject(format!("canonicalize: {}", e)),
    };
    let expected = sha256_hashref(canonical_packet.as_bytes());
    if expected != proof.packet_hash {
        return reject("packet_hash mismatch".into());
    }
    if proof.signature.signer != proof.relay {
        return reject("proof signer != relay".into());
    }
    let mut sig_value = match serde_json::to_value(proof) {
        Ok(v) => v,
        Err(e) => return reject(format!("serde: {}", e)),
    };
    if let serde_json::Value::Object(map) = &mut sig_value {
        map.remove("signature");
    }
    let sig_canonical = match canonicalize(&sig_value) {
        Ok(c) => c,
        Err(e) => return reject(format!("canonicalize: {}", e)),
    };
    let sig_bytes = match STANDARD.decode(&proof.signature.signature) {
        Ok(b) => b,
        Err(e) => return reject(format!("signature base64: {}", e)),
    };
    let sig = match Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(e) => return reject(format!("signature parse: {}", e)),
    };
    let vk = match VerifyingKey::from_bytes(relay_public_key) {
        Ok(v) => v,
        Err(e) => return reject(format!("verifying key: {}", e)),
    };
    if vk.verify(sig_canonical.as_bytes(), &sig).is_err() {
        return reject("forwarding signature did not verify".into());
    }
    VerifyResult {
        ok: true,
        reason: None,
    }
}

fn reject(reason: String) -> VerifyResult {
    VerifyResult {
        ok: false,
        reason: Some(reason),
    }
}

/* -------------------------------------------------------------------------- */
/*  Tests                                                                      */
/* -------------------------------------------------------------------------- */

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Ed25519Signer;
    use crate::packet::{sign_packet, SignPacketArgs};
    use rand::rngs::OsRng;
    use rand::RngCore;

    fn fresh_seed() -> [u8; 32] {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        seed
    }

    fn fixture_packet(packet_id: &str, expires_at: Option<&str>, created_at: &str) -> Packet {
        let signer_seed = fresh_seed();
        sign_packet(SignPacketArgs {
            packet_id: packet_id.into(),
            source: "tf:actor:agent:example.com/x".into(),
            destination: "tf:actor:service:example.com/d".into(),
            priority: "P3".into(),
            payload: b"hi",
            encoding: None,
            compression: None,
            emergency: false,
            expires_at: expires_at.map(str::to_string),
            ttl_hops: None,
            route_constraints: None,
            session_ref: None,
            private_key: signer_seed,
            signer: "tf:actor:agent:example.com/x".into(),
            created_at: Some(created_at.into()),
        })
        .expect("sign")
    }

    #[test]
    fn packet_receiver_accepts_then_rejects_replay() {
        let mut recv = PacketReceiver::new(None);
        let p = fixture_packet("pkt-A", None, "2026-04-24T12:00:00Z");
        assert_eq!(recv.observe(&p, "2026-04-24T13:00:00Z"), PacketReceiverDecision::Accept);
        assert!(matches!(
            recv.observe(&p, "2026-04-24T13:00:00Z"),
            PacketReceiverDecision::Reject {
                reason: PacketRejectReason::Replay
            }
        ));
    }

    #[test]
    fn packet_receiver_rejects_expired() {
        let mut recv = PacketReceiver::new(None);
        let p = fixture_packet(
            "pkt-old",
            Some("2026-04-23T00:00:00Z"),
            "2026-04-22T00:00:00Z",
        );
        assert!(matches!(
            recv.observe(&p, "2026-04-24T12:00:00Z"),
            PacketReceiverDecision::Reject {
                reason: PacketRejectReason::Expired
            }
        ));
    }

    #[test]
    fn packet_receiver_rejects_future_dated() {
        let mut recv = PacketReceiver::new(None);
        let p = fixture_packet("pkt-future", None, "2099-04-24T12:00:00Z");
        assert!(matches!(
            recv.observe(&p, "2026-04-24T12:00:00Z"),
            PacketReceiverDecision::Reject {
                reason: PacketRejectReason::FutureDated
            }
        ));
    }

    #[test]
    fn packet_receiver_lru_evicts_oldest() {
        let mut recv = PacketReceiver::new(Some(2));
        for i in 0..3 {
            let p = fixture_packet(
                &format!("pkt-{}", i),
                None,
                "2026-04-24T11:00:00Z",
            );
            assert_eq!(recv.observe(&p, "2026-04-24T12:00:00Z"), PacketReceiverDecision::Accept);
        }
        assert_eq!(recv.size(), 2);
    }

    #[test]
    fn orl_runtime_load_and_lookup() {
        let issuer = Ed25519Signer::from_bytes(&fresh_seed());
        let issuer_pub = issuer.public_key_bytes();
        let issuer_priv = {
            // Need raw seed bytes for sign_offline_revocation_list. Use
            // a known seed for deterministic test; we keep the seed
            // around since we sign with it directly below.
            let seed = fresh_seed();
            seed
        };
        let issuer_signer = Ed25519Signer::from_bytes(&issuer_priv);
        let issuer_pub2 = issuer_signer.public_key_bytes();
        let draft = OfflineRevocationList {
            list_version: OfflineRevocationList_ListVersion::V1,
            trust_domain: "example.com".into(),
            issued_at: "2026-04-24T00:00:00Z".into(),
            valid_until: "2026-04-30T00:00:00Z".into(),
            issuer: "tf:actor:service:example.com/tf-daemon".into(),
            revoked: vec![
                RevokedEntry {
                    kind: RevokedEntry_Kind::Actor,
                    id: "tf:actor:agent:example.com/bad".into(),
                    reason: Some("compromised".into()),
                    revoked_at: None,
                },
                RevokedEntry {
                    kind: RevokedEntry_Kind::Key,
                    id: "kid-42".into(),
                    reason: None,
                    revoked_at: None,
                },
            ],
            signature: crate::generated::common::SignatureEnvelope {
                algorithm: "ed25519".to_string(),
                signer: "tf:actor:service:example.com/tf-daemon".into(),
                signature: String::new(),
                hash_alg: None,
                alt_algorithm: None,
                alt_signature: None,
            },
        };
        let _ = issuer_pub; // suppress warning if unused
        let signed = sign_offline_revocation_list(draft, &issuer_priv).expect("sign");
        let runtime = OfflineRevocationListRuntime::load(signed.clone(), &issuer_pub2, "2026-04-25T00:00:00Z")
            .expect("load");
        assert!(runtime
            .is_revoked(&RevokedEntry_Kind::Actor, "tf:actor:agent:example.com/bad")
            .is_some());
        assert!(runtime.is_revoked(&RevokedEntry_Kind::Key, "kid-42").is_some());
        assert!(runtime
            .is_revoked(&RevokedEntry_Kind::Actor, "tf:actor:agent:example.com/ok")
            .is_none());
    }

    #[test]
    fn orl_runtime_rejects_expired() {
        let issuer_priv = fresh_seed();
        let issuer_pub = Ed25519Signer::from_bytes(&issuer_priv).public_key_bytes();
        let draft = OfflineRevocationList {
            list_version: OfflineRevocationList_ListVersion::V1,
            trust_domain: "example.com".into(),
            issued_at: "2026-04-24T00:00:00Z".into(),
            valid_until: "2026-04-30T00:00:00Z".into(),
            issuer: "tf:actor:service:example.com/tf-daemon".into(),
            revoked: Vec::new(),
            signature: crate::generated::common::SignatureEnvelope {
                algorithm: "ed25519".to_string(),
                signer: "tf:actor:service:example.com/tf-daemon".into(),
                signature: String::new(),
                hash_alg: None,
                alt_algorithm: None,
                alt_signature: None,
            },
        };
        let signed = sign_offline_revocation_list(draft, &issuer_priv).expect("sign");
        let r = OfflineRevocationListRuntime::load(signed, &issuer_pub, "2026-05-15T00:00:00Z");
        assert!(matches!(r, Err(OrlError::Expired(_))));
    }

    #[test]
    fn orl_runtime_rejects_forged_signature() {
        let issuer_priv = fresh_seed();
        let other_pub = Ed25519Signer::from_bytes(&fresh_seed()).public_key_bytes();
        let draft = OfflineRevocationList {
            list_version: OfflineRevocationList_ListVersion::V1,
            trust_domain: "example.com".into(),
            issued_at: "2026-04-24T00:00:00Z".into(),
            valid_until: "2026-04-30T00:00:00Z".into(),
            issuer: "tf:actor:service:example.com/tf-daemon".into(),
            revoked: Vec::new(),
            signature: crate::generated::common::SignatureEnvelope {
                algorithm: "ed25519".to_string(),
                signer: "tf:actor:service:example.com/tf-daemon".into(),
                signature: String::new(),
                hash_alg: None,
                alt_algorithm: None,
                alt_signature: None,
            },
        };
        let signed = sign_offline_revocation_list(draft, &issuer_priv).expect("sign");
        let r = OfflineRevocationListRuntime::load(signed, &other_pub, "2026-04-25T00:00:00Z");
        assert!(matches!(r, Err(OrlError::BadSignature)));
    }

    #[test]
    fn delivery_receipt_round_trip() {
        let receiver_priv = fresh_seed();
        let receiver_pub = Ed25519Signer::from_bytes(&receiver_priv).public_key_bytes();
        let p = fixture_packet("pkt-deliver-1", None, "2026-04-24T12:00:00Z");
        let receipt = sign_delivery_receipt(
            &p,
            "tf:actor:agent:example.com/receiver",
            "2026-04-24T12:01:00Z",
            &receiver_priv,
        )
        .expect("sign");
        let v = verify_delivery_receipt(&receipt, &p, &receiver_pub);
        assert!(v.ok);
    }

    #[test]
    fn delivery_receipt_rejects_packet_mismatch() {
        let receiver_priv = fresh_seed();
        let receiver_pub = Ed25519Signer::from_bytes(&receiver_priv).public_key_bytes();
        let p1 = fixture_packet("pkt-1", None, "2026-04-24T12:00:00Z");
        let p2 = fixture_packet("pkt-2", None, "2026-04-24T12:00:00Z");
        let receipt = sign_delivery_receipt(
            &p1,
            "tf:actor:agent:example.com/receiver",
            "2026-04-24T12:01:00Z",
            &receiver_priv,
        )
        .expect("sign");
        let v = verify_delivery_receipt(&receipt, &p2, &receiver_pub);
        assert!(!v.ok);
        assert_eq!(v.reason.as_deref(), Some("packet_id mismatch"));
    }

    #[test]
    fn proof_of_forwarding_round_trip_and_tamper() {
        let relay_priv = fresh_seed();
        let relay_pub = Ed25519Signer::from_bytes(&relay_priv).public_key_bytes();
        let p = fixture_packet("pkt-relay-1", None, "2026-04-24T12:00:00Z");
        let proof = sign_proof_of_forwarding(
            &p,
            "tf:actor:relay:example.com/edge",
            "2026-04-24T12:01:00Z",
            1,
            &relay_priv,
        )
        .expect("sign");
        let v = verify_proof_of_forwarding(&proof, &p, &relay_pub);
        assert!(v.ok);
        // Tamper the forwarded_at — re-canonicalised body no longer
        // matches the signature, verifier rejects.
        let tampered = ProofOfForwarding {
            forwarded_at: "2027-01-01T00:00:00Z".into(),
            ..proof.clone()
        };
        let v2 = verify_proof_of_forwarding(&tampered, &p, &relay_pub);
        assert!(!v2.ok);
    }
}
