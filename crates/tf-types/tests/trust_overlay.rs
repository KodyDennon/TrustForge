//! Trust-overlay parity tests over `conformance/trust-overlay-vectors.yaml`.

use std::fs;
use std::path::PathBuf;

use serde::Deserialize;

use tf_types::generated::{ActorIdentity, TrustLevel};
use tf_types::trust_overlay::{compose_trust_level, PostureContext};

#[derive(Deserialize)]
struct VectorFile {
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    identity: ActorIdentity,
    posture: PostureContext,
    level: String,
}

fn load() -> VectorFile {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("conformance")
        .join("trust-overlay-vectors.yaml");
    let raw = fs::read_to_string(&path).unwrap();
    tf_types::yaml::from_str(&raw).expect("parse trust-overlay-vectors.yaml")
}

fn level_to_str(level: &TrustLevel) -> &'static str {
    match level {
        TrustLevel::T0 => "T0",
        TrustLevel::T1 => "T1",
        TrustLevel::T2 => "T2",
        TrustLevel::T3 => "T3",
        TrustLevel::T4 => "T4",
        TrustLevel::T5 => "T5",
        TrustLevel::T6 => "T6",
        TrustLevel::T7 => "T7",
    }
}

#[test]
fn parity_vectors_match() {
    for v in load().vectors {
        let result = compose_trust_level(&v.identity, &v.posture);
        assert_eq!(level_to_str(&result.level), v.level, "vector {}", v.name);
        assert!(result
            .reasons
            .first()
            .map(|r| r.starts_with("base=T"))
            .unwrap_or(false));
    }
}

#[test]
fn untrusted_relay_does_not_reduce_below_t0() {
    let identity = sample_identity(vec![TrustLevel::T0]);
    let r = compose_trust_level(
        &identity,
        &PostureContext {
            untrusted_relay_path: true,
            ..PostureContext::default()
        },
    );
    assert_eq!(r.level, TrustLevel::T0);
}

#[test]
fn highest_boost_wins_when_multiple_apply() {
    let identity = sample_identity(vec![TrustLevel::T2]);
    let r = compose_trust_level(
        &identity,
        &PostureContext {
            hardware_backed: true,
            quorum_approvers_at_least: Some(2),
            publicly_anchored: true,
            compliance_attested: true,
            ..PostureContext::default()
        },
    );
    assert_eq!(r.level, TrustLevel::T7);
}

#[test]
fn no_levels_starts_at_t0() {
    let identity = sample_identity(vec![]);
    let r = compose_trust_level(&identity, &PostureContext::default());
    assert_eq!(r.level, TrustLevel::T0);
}

#[test]
fn reasons_trace_records_every_adjustment() {
    let identity = sample_identity(vec![TrustLevel::T2]);
    let r = compose_trust_level(
        &identity,
        &PostureContext {
            hardware_backed: true,
            untrusted_relay_path: true,
            ..PostureContext::default()
        },
    );
    assert_eq!(r.level, TrustLevel::T3);
    assert!(r.reasons.iter().any(|s| s == "hardware-backed → ≥T4"));
    assert!(r.reasons.iter().any(|s| s == "untrusted relay path → -1"));
}

fn sample_identity(levels: Vec<TrustLevel>) -> ActorIdentity {
    use tf_types::generated::{
        ActorIdentity_IdentityVersion, ActorType, AuthorityRoot, AuthorityRoot_Kind, PublicKey,
        PublicKey_Purpose,
    };
    ActorIdentity {
        identity_version: ActorIdentity_IdentityVersion::V1,
        actor_id: "tf:actor:human:example.com/u".into(),
        actor_type: ActorType::Human,
        instance_id: None,
        public_keys: vec![PublicKey {
            key_id: "k".into(),
            algorithm: "ed25519".into(),
            public_key: "AA==".into(),
            purpose: PublicKey_Purpose::Signing,
            valid_from: None,
            valid_until: None,
        }],
        trust_levels: levels,
        authority_roots: vec![AuthorityRoot {
            kind: AuthorityRoot_Kind::Organization,
            id: "example.com".into(),
        }],
        attestations: None,
        valid_from: "2026-01-01T00:00:00Z".into(),
        valid_until: None,
        revocation_ref: None,
        signature: None,
    }
}
