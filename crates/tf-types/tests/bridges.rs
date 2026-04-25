//! SPIFFE bridge tests + cross-language parity against
//! `conformance/bridge-vectors.yaml`.

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use serde::Deserialize;

use tf_types::bridge_spiffe::{actor_id_to_spiffe, spiffe_to_actor_id, SpiffeBridge};
use tf_types::bridges::{Bridge, BridgeError, BridgeKind, BridgeRegistry};

#[derive(Deserialize)]
struct VectorsFile {
    spiffe: Vec<SpiffeVec>,
}

#[derive(Deserialize)]
struct SpiffeVec {
    name: String,
    spiffe_id: String,
    actor_id: String,
}

fn load_vectors() -> VectorsFile {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("conformance")
        .join("bridge-vectors.yaml");
    let raw = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
    serde_yaml::from_str(&raw).expect("parse bridge-vectors.yaml")
}

#[test]
fn spiffe_forward_matches_vectors() {
    for v in &load_vectors().spiffe {
        let got = spiffe_to_actor_id(&v.spiffe_id).expect(&v.name);
        assert_eq!(got, v.actor_id, "{} forward", v.name);
    }
}

#[test]
fn spiffe_reverse_matches_vectors() {
    for v in &load_vectors().spiffe {
        let got = actor_id_to_spiffe(&v.actor_id).expect(&v.name);
        assert_eq!(got, v.spiffe_id, "{} reverse", v.name);
    }
}

#[test]
fn spiffe_rejects_bad_input() {
    assert!(matches!(
        spiffe_to_actor_id("urn:spiffe:foo"),
        Err(BridgeError::InvalidInput(_))
    ));
    assert!(matches!(
        spiffe_to_actor_id(""),
        Err(BridgeError::InvalidInput(_))
    ));
    assert!(matches!(
        spiffe_to_actor_id("spiffe://domain"),
        Err(BridgeError::InvalidInput(_))
    ));
}

#[test]
fn spiffe_reverse_rejects_non_service_actors() {
    assert!(matches!(
        actor_id_to_spiffe("tf:actor:human:example.com/kody"),
        Err(BridgeError::Unsupported(_))
    ));
    assert!(matches!(
        actor_id_to_spiffe("not-an-actor"),
        Err(BridgeError::InvalidInput(_))
    ));
}

#[test]
fn registry_finds_spiffe_bridge_by_kind() {
    let mut registry = BridgeRegistry::new();
    registry.register(Arc::new(SpiffeBridge::new("tf-spiffe-bridge", "example.org")));
    let found = registry.get(BridgeKind::Spiffe).expect("found");
    assert_eq!(found.bridge_id(), "tf-spiffe-bridge");
    assert_eq!(found.trust_domain(), "example.org");
    assert!(matches!(found.kind(), BridgeKind::Spiffe));
}
