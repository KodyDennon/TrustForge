//! Proof-event chain and merkle-tree helpers.
//!
//! Matches `tools/tf-types-ts/src/core/chain.ts` byte-for-byte via
//! `conformance/chain-vectors.yaml`.
//!
//! - `event_hash(event)` → `sha256:<hex>` over the canonical JSON of the
//!   event with its `signature` field removed. This is the bytes a signer
//!   actually signs; putting the signature inside the event would make the
//!   hash self-referential.
//! - `verify_chain(events)` → asserts every `events[i].parent_hash` equals
//!   `event_hash(events[i-1])` for i > 0 (the first event has no parent).
//! - `merkle_root(events)` → sha256 over pair-wise concatenated hashes,
//!   duplicating the last leaf at each odd level (Bitcoin convention).
//! - `chain_hash(events)` → rolling sha256(prev || event_hash) seeded with
//!   32 zero bytes.

use std::fmt::Write;

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::canonical::{canonicalize, CanonicalJsonError};
use crate::crypto::parse_hashref;
use crate::generated::proof_event::ProofEvent;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ChainError {
    #[error("canonical JSON error: {0}")]
    Canonical(String),
    #[error("serialization error: {0}")]
    Serialize(String),
    #[error("invalid hash ref in chain: {0}")]
    BadHashRef(String),
    #[error("event {0} declares parent_hash {1:?} but previous event hashes to {2:?}")]
    ParentMismatch(usize, String, String),
    #[error("event {0} is not the first but has no parent_hash")]
    MissingParentHash(usize),
}

impl From<CanonicalJsonError> for ChainError {
    fn from(e: CanonicalJsonError) -> Self {
        ChainError::Canonical(e.to_string())
    }
}

/// Canonical JSON of an event with its signature stripped.
pub fn event_signed_payload(event: &ProofEvent) -> Result<String, ChainError> {
    let mut v = serde_json::to_value(event).map_err(|e| ChainError::Serialize(e.to_string()))?;
    if let Value::Object(ref mut map) = v {
        map.remove("signature");
    }
    Ok(canonicalize(&v)?)
}

/// The `sha256:<hex>` hash of an event's signed payload.
pub fn event_hash(event: &ProofEvent) -> Result<String, ChainError> {
    let payload = event_signed_payload(event)?;
    Ok(sha256_hash_of(payload.as_bytes()))
}

fn sha256_hash_of(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("sha256:{}", hex_lower(&digest))
}

pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(s, "{:02x}", b).unwrap();
    }
    s
}

/// Verify a chain of events. `events[0]` may have no `parent_hash`; every
/// subsequent event must declare `parent_hash == event_hash(events[i-1])`.
pub fn verify_chain(events: &[ProofEvent]) -> Result<(), ChainError> {
    for i in 1..events.len() {
        let expected = event_hash(&events[i - 1])?;
        let Some(parent) = &events[i].parent_hash else {
            return Err(ChainError::MissingParentHash(i));
        };
        if parent != &expected {
            return Err(ChainError::ParentMismatch(i, parent.clone(), expected));
        }
    }
    Ok(())
}

/// Merkle root over the event hashes. Empty trees return a sentinel zero
/// hash; single-event trees return that event's hash; otherwise pair-wise
/// hash up, duplicating the last leaf when a level has an odd number of
/// nodes.
pub fn merkle_root(events: &[ProofEvent]) -> Result<String, ChainError> {
    if events.is_empty() {
        return Ok(format!("sha256:{}", hex_lower(&[0u8; 32])));
    }
    let mut level: Vec<Vec<u8>> = events
        .iter()
        .map(|e| {
            let hash = event_hash(e)?;
            parse_hashref(&hash)
                .map(|(_, bytes)| bytes)
                .map_err(|err| ChainError::BadHashRef(err.to_string()))
        })
        .collect::<Result<_, ChainError>>()?;
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(level.last().unwrap().clone());
        }
        let mut next: Vec<Vec<u8>> = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks_exact(2) {
            let mut hasher = Sha256::new();
            hasher.update(&pair[0]);
            hasher.update(&pair[1]);
            next.push(hasher.finalize().to_vec());
        }
        level = next;
    }
    Ok(format!("sha256:{}", hex_lower(&level[0])))
}

/// Rolling chain hash: seeded with 32 zero bytes, then for each event the
/// hash is `sha256(prev || sha256_bytes_of_event)`.
pub fn chain_hash(events: &[ProofEvent]) -> Result<String, ChainError> {
    let mut state = vec![0u8; 32];
    for e in events {
        let (_, event_bytes) = parse_hashref(&event_hash(e)?).map_err(|err| ChainError::BadHashRef(err.to_string()))?;
        let mut hasher = Sha256::new();
        hasher.update(&state);
        hasher.update(&event_bytes);
        state = hasher.finalize().to_vec();
    }
    Ok(format!("sha256:{}", hex_lower(&state)))
}

/// Minimal serialization helper used by tests that need to serialize an
/// arbitrary Serialize value to canonical JSON.
pub fn canonical_of<S: Serialize>(v: &S) -> Result<String, ChainError> {
    let json = serde_json::to_value(v).map_err(|e| ChainError::Serialize(e.to_string()))?;
    Ok(canonicalize(&json)?)
}
