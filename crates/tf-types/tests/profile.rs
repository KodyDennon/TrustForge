//! Profile selection runtime parity tests — Rust mirror of
//! `tools/tf-types-ts/tests/profile.test.ts`.

use std::collections::BTreeSet;

use tf_types::generated::common::{EnforcementLevel, ProofLevel};
use tf_types::profile::{builtin_profile, builtin_profiles, select_profile, ProfileFeatureGate};

fn set<I, S>(items: I) -> BTreeSet<String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    items.into_iter().map(|s| s.into()).collect()
}

fn home_features() -> BTreeSet<String> {
    set(["agent-contract", "proof-log", "ed25519", "vault"])
}

fn ent_features() -> BTreeSet<String> {
    set([
        "policy-engine",
        "quorum-collector",
        "continuous-reauth",
        "transparency-anchor.any",
        "federation",
        "webauthn",
        "agent-contract",
    ])
}

fn const_features() -> BTreeSet<String> {
    set([
        "packet-mode",
        "fragment-reassembly",
        "offline-revocation-list",
        "emergency-authority",
    ])
}

fn comp_features() -> BTreeSet<String> {
    set([
        "policy-engine",
        "quorum-collector",
        "signed-log-events",
        "evidence-bundle",
        "l4-encrypted-bundle",
        "l5-rfc3161-anchor",
        "continuous-reauth",
    ])
}

#[test]
fn home_profile_passes_with_full_feature_set() {
    let spec = builtin_profile("tf-home-compatible").unwrap();
    let gate = ProfileFeatureGate {
        features: home_features(),
        enforcement_level: EnforcementLevel::E3,
        proof_level_floor: ProofLevel::L1,
        bridges: BTreeSet::new(),
        anchors: set(["memory"]),
    };
    let v = select_profile(&spec, &gate);
    assert!(v.ok, "failures: {:?}", v.failures);
    assert!(v.failures.is_empty());
    assert_eq!(v.profile, "tf-home-compatible");
}

#[test]
fn enterprise_profile_passes_with_bridges_and_anchors() {
    let spec = builtin_profile("tf-enterprise-compatible").unwrap();
    let gate = ProfileFeatureGate {
        features: ent_features(),
        enforcement_level: EnforcementLevel::E4,
        proof_level_floor: ProofLevel::L2,
        bridges: set(["webauthn", "oauth", "spiffe"]),
        anchors: set(["rfc6962"]),
    };
    let v = select_profile(&spec, &gate);
    assert!(v.ok, "failures: {:?}", v.failures);
}

#[test]
fn constrained_profile_passes_with_packet_features() {
    let spec = builtin_profile("tf-constrained-compatible").unwrap();
    let gate = ProfileFeatureGate {
        features: const_features(),
        enforcement_level: EnforcementLevel::E3,
        proof_level_floor: ProofLevel::L1,
        bridges: BTreeSet::new(),
        anchors: BTreeSet::new(),
    };
    let v = select_profile(&spec, &gate);
    assert!(v.ok, "failures: {:?}", v.failures);
}

#[test]
fn compliance_profile_passes_with_both_anchors() {
    let spec = builtin_profile("tf-compliance-evidence-compatible").unwrap();
    let gate = ProfileFeatureGate {
        features: comp_features(),
        enforcement_level: EnforcementLevel::E4,
        proof_level_floor: ProofLevel::L3,
        bridges: BTreeSet::new(),
        anchors: set(["rfc6962", "rfc3161"]),
    };
    let v = select_profile(&spec, &gate);
    assert!(v.ok, "failures: {:?}", v.failures);
}

#[test]
fn missing_must_feature_fails() {
    let spec = builtin_profile("tf-home-compatible").unwrap();
    let mut features = home_features();
    features.remove("vault");
    let gate = ProfileFeatureGate {
        features,
        enforcement_level: EnforcementLevel::E3,
        proof_level_floor: ProofLevel::L1,
        bridges: BTreeSet::new(),
        anchors: BTreeSet::new(),
    };
    let v = select_profile(&spec, &gate);
    assert!(!v.ok);
    assert!(v.failures.iter().any(|f| f.contains("\"vault\"")));
}

#[test]
fn forbidden_feature_fails_constrained_profile() {
    let spec = builtin_profile("tf-constrained-compatible").unwrap();
    let mut features = const_features();
    features.insert("transport.websocket-only".to_string());
    let gate = ProfileFeatureGate {
        features,
        enforcement_level: EnforcementLevel::E3,
        proof_level_floor: ProofLevel::L1,
        bridges: BTreeSet::new(),
        anchors: BTreeSet::new(),
    };
    let v = select_profile(&spec, &gate);
    assert!(!v.ok);
    assert!(v.failures.iter().any(|f| f.contains("forbids")));
}

#[test]
fn enforcement_below_floor_fails() {
    let spec = builtin_profile("tf-home-compatible").unwrap();
    let gate = ProfileFeatureGate {
        features: home_features(),
        enforcement_level: EnforcementLevel::E1,
        proof_level_floor: ProofLevel::L1,
        bridges: BTreeSet::new(),
        anchors: BTreeSet::new(),
    };
    let v = select_profile(&spec, &gate);
    assert!(!v.ok);
    assert!(v.failures.iter().any(|f| f.contains("EnforcementLevel")));
}

#[test]
fn proof_floor_below_required_fails() {
    let spec = builtin_profile("tf-enterprise-compatible").unwrap();
    let gate = ProfileFeatureGate {
        features: ent_features(),
        enforcement_level: EnforcementLevel::E4,
        proof_level_floor: ProofLevel::L1,
        bridges: set(["webauthn", "oauth", "spiffe"]),
        anchors: set(["rfc6962"]),
    };
    let v = select_profile(&spec, &gate);
    assert!(!v.ok);
    assert!(v.failures.iter().any(|f| f.contains("proof level floor")));
}

#[test]
fn missing_required_bridge_fails() {
    let spec = builtin_profile("tf-enterprise-compatible").unwrap();
    let gate = ProfileFeatureGate {
        features: ent_features(),
        enforcement_level: EnforcementLevel::E4,
        proof_level_floor: ProofLevel::L2,
        bridges: set(["webauthn", "oauth"]),
        anchors: set(["rfc6962"]),
    };
    let v = select_profile(&spec, &gate);
    assert!(!v.ok);
    assert!(v.failures.iter().any(|f| f.contains("bridge spiffe")));
}

#[test]
fn missing_required_anchor_fails() {
    let spec = builtin_profile("tf-compliance-evidence-compatible").unwrap();
    let gate = ProfileFeatureGate {
        features: comp_features(),
        enforcement_level: EnforcementLevel::E4,
        proof_level_floor: ProofLevel::L3,
        bridges: BTreeSet::new(),
        anchors: set(["rfc6962"]),
    };
    let v = select_profile(&spec, &gate);
    assert!(!v.ok);
    assert!(v.failures.iter().any(|f| f.contains("rfc3161")));
}

#[test]
fn missing_should_feature_is_a_warning_not_a_failure() {
    let spec = builtin_profile("tf-home-compatible").unwrap();
    let gate = ProfileFeatureGate {
        features: home_features(),
        enforcement_level: EnforcementLevel::E3,
        proof_level_floor: ProofLevel::L1,
        bridges: BTreeSet::new(),
        anchors: BTreeSet::new(),
    };
    let v = select_profile(&spec, &gate);
    assert!(v.ok);
    assert_eq!(v.warnings.len(), 2);
    assert!(v.warnings.iter().any(|w| w.contains("webauthn")));
    assert!(v.warnings.iter().any(|w| w.contains("shadow-mode")));
}

#[test]
fn builtin_profiles_returns_four_profiles() {
    let profiles = builtin_profiles();
    assert_eq!(profiles.len(), 4);
    let ids: Vec<&str> = profiles.iter().map(|p| p.profile_id.as_str()).collect();
    assert!(ids.contains(&"tf-home-compatible"));
    assert!(ids.contains(&"tf-enterprise-compatible"));
    assert!(ids.contains(&"tf-constrained-compatible"));
    assert!(ids.contains(&"tf-compliance-evidence-compatible"));
}
