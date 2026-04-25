//! Rust side of the chain-vectors parity suite. Must produce the same
//! merkle roots, chain hashes, and chain-validity verdicts as the TS side.

use std::fs;
use std::path::PathBuf;

use serde::Deserialize;
use serde_json::Value;

use tf_types::chain::{chain_hash, event_hash, merkle_root, verify_chain};
use tf_types::generated::proof_event::ProofEvent;

#[derive(Deserialize)]
struct VectorsFile {
    cases: Vec<ChainCase>,
}

#[derive(Deserialize)]
struct ChainCase {
    name: String,
    events: Vec<Value>,
    expect: ChainExpect,
}

#[derive(Deserialize)]
struct ChainExpect {
    chain_valid: bool,
    first_event_hash: Option<String>,
    merkle_root: Option<String>,
    chain_hash: Option<String>,
}

fn load_vectors() -> VectorsFile {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("conformance")
        .join("chain-vectors.yaml");
    let raw = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
    serde_yaml::from_str(&raw).expect("parse chain-vectors.yaml")
}

fn realize_chain(raw: &[Value]) -> Vec<ProofEvent> {
    let mut out: Vec<ProofEvent> = Vec::with_capacity(raw.len());
    for (i, v) in raw.iter().enumerate() {
        let mut patched = v.clone();
        if let Value::Object(ref mut map) = patched {
            if let Some(ph) = map.get("parent_hash").cloned() {
                if ph.as_str() == Some("__derive_from_prev__") {
                    let h = event_hash(&out[i - 1]).expect("event_hash");
                    map.insert("parent_hash".to_string(), Value::String(h));
                }
            }
        }
        out.push(serde_json::from_value(patched).expect("parse event"));
    }
    out
}

#[test]
fn chain_verification_matches_expectation() {
    for c in &load_vectors().cases {
        let events = realize_chain(&c.events);
        let result = verify_chain(&events);
        match (c.expect.chain_valid, result.is_ok()) {
            (true, true) | (false, false) => {}
            (expected, got) => panic!(
                "{}: expected chain_valid={}, got valid={}",
                c.name, expected, got
            ),
        }
    }
}

#[test]
fn hashes_match_pinned_vectors() {
    for c in &load_vectors().cases {
        let events = realize_chain(&c.events);
        if let Some(expected) = &c.expect.first_event_hash {
            assert_eq!(&event_hash(&events[0]).expect("hash"), expected, "{} first_event_hash", c.name);
        }
        if let Some(expected) = &c.expect.merkle_root {
            assert_eq!(&merkle_root(&events).expect("merkle"), expected, "{} merkle_root", c.name);
        }
        if let Some(expected) = &c.expect.chain_hash {
            assert_eq!(&chain_hash(&events).expect("chain_hash"), expected, "{} chain_hash", c.name);
        }
    }
}

#[test]
fn single_event_merkle_equals_event_hash() {
    let cases = load_vectors();
    let events = realize_chain(&cases.cases[0].events);
    assert_eq!(
        merkle_root(&events).expect("merkle"),
        event_hash(&events[0]).expect("hash")
    );
}

#[test]
fn empty_merkle_is_zero_sentinel() {
    assert_eq!(
        merkle_root(&[]).expect("merkle"),
        format!("sha256:{}", "00".repeat(32))
    );
}
