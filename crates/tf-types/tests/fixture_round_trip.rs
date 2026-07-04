//! Round-trips every valid fixture through its generated Rust type and
//! asserts the re-serialized JSON preserves the original data. Catches
//! field naming drift between schema and generated struct.

use std::{fs, path::Path};

use tf_types::generated::{
    actions::Actions, actor_identity::ActorIdentity, agent_contract::AgentContract,
    capability_token::CapabilityToken, conformance::Conformance, policy::Policy,
    proof_bundle::ProofBundle, proof_event::ProofEvent, proof_profile::ProofProfile,
    revocation::Revocation, threat_model::ThreatModel,
};

fn fixture_path(schema: &str, which: &str, name: &str) -> String {
    format!(
        "{}/../../schemas/fixtures/{}/{}/{}.yaml",
        env!("CARGO_MANIFEST_DIR"),
        schema,
        which,
        name
    )
}

fn yaml_to_json(yaml: &str) -> serde_json::Value {
    let v: serde_json::Value = tf_types::yaml::from_str(yaml).unwrap();
    serde_json::to_value(v).unwrap()
}

fn round_trip<T: serde::de::DeserializeOwned + serde::Serialize>(path: &str) {
    let yaml = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {}", path, e));
    let original = yaml_to_json(&yaml);
    let typed: T = serde_json::from_value(original.clone())
        .unwrap_or_else(|e| panic!("deserialize {} into typed form: {}", path, e));
    let reserialized = serde_json::to_value(&typed).unwrap();
    assert_json_eq(&original, &reserialized, Path::new(path));
}

fn assert_json_eq(a: &serde_json::Value, b: &serde_json::Value, path: &Path) {
    // Any field missing on one side that's null/absent on the other is fine,
    // but values that are present on both must match.
    match (a, b) {
        (serde_json::Value::Object(oa), serde_json::Value::Object(ob)) => {
            for (k, va) in oa {
                if let Some(vb) = ob.get(k) {
                    assert_json_eq(va, vb, path);
                } else if !va.is_null() {
                    panic!("{:?}: missing field {} in round-trip output", path, k);
                }
            }
            for (k, vb) in ob {
                if !oa.contains_key(k) && !vb.is_null() {
                    panic!("{:?}: extra field {} in round-trip output", path, k);
                }
            }
        }
        (serde_json::Value::Array(xa), serde_json::Value::Array(xb)) => {
            assert_eq!(xa.len(), xb.len(), "{:?}: array length mismatch", path);
            for (va, vb) in xa.iter().zip(xb.iter()) {
                assert_json_eq(va, vb, path);
            }
        }
        _ => assert_eq!(a, b, "value mismatch in {:?}", path),
    }
}

#[test]
fn agent_contract_minimal() {
    round_trip::<AgentContract>(&fixture_path("agent-contract", "valid", "minimal"));
}

#[test]
fn policy_basic() {
    round_trip::<Policy>(&fixture_path("policy", "valid", "basic"));
}

#[test]
fn threat_model_basic() {
    round_trip::<ThreatModel>(&fixture_path("threat-model", "valid", "basic"));
}

#[test]
fn actions_basic() {
    round_trip::<Actions>(&fixture_path("actions", "valid", "basic"));
}

#[test]
fn proof_profile_basic() {
    round_trip::<ProofProfile>(&fixture_path("proof-profile", "valid", "basic"));
}

#[test]
fn conformance_basic() {
    round_trip::<Conformance>(&fixture_path("conformance", "valid", "basic"));
}

#[test]
fn actor_identity_basic() {
    round_trip::<ActorIdentity>(&fixture_path("actor-identity", "valid", "basic"));
}

#[test]
fn capability_token_basic() {
    round_trip::<CapabilityToken>(&fixture_path("capability-token", "valid", "basic"));
}

#[test]
fn capability_token_composite() {
    round_trip::<CapabilityToken>(&fixture_path(
        "capability-token",
        "composite",
        "delegation-chain",
    ));
}

#[test]
fn revocation_basic() {
    round_trip::<Revocation>(&fixture_path("revocation", "valid", "basic"));
}

#[test]
fn proof_event_basic() {
    round_trip::<ProofEvent>(&fixture_path("proof-event", "valid", "basic"));
}

#[test]
fn proof_bundle_basic() {
    round_trip::<ProofBundle>(&fixture_path("proof-bundle", "valid", "basic"));
}
