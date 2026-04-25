//! Profile selection runtime — Rust mirror of `tools/tf-types-ts/src/core/profile.ts`.
//!
//! `select_profile(spec, gate)` checks a `ProfileSpec` (parsed from
//! profile-spec.schema.json) against a `ProfileFeatureGate` describing
//! the running daemon. Built-in profiles are exposed via
//! [`builtin_profiles`].

use std::collections::BTreeSet;

use crate::generated::common::{EnforcementLevel, ProofLevel};
use crate::generated::profile_spec::{
    Feature, ProfileSpec, ProfileSpec_MinEnforcementLevel, ProfileSpec_ProfileVersion,
    ProfileSpec_RequiredAnchors_Item,
};

#[derive(Debug, Clone)]
pub struct ProfileFeatureGate {
    pub features: BTreeSet<String>,
    pub enforcement_level: EnforcementLevel,
    pub proof_level_floor: ProofLevel,
    pub bridges: BTreeSet<String>,
    pub anchors: BTreeSet<String>,
}

#[derive(Debug, Clone)]
pub struct ProfileVerdict {
    pub ok: bool,
    pub profile: String,
    pub failures: Vec<String>,
    pub warnings: Vec<String>,
}

fn enf_rank(e: &EnforcementLevel) -> u8 {
    match e {
        EnforcementLevel::E0 => 0,
        EnforcementLevel::E1 => 1,
        EnforcementLevel::E2 => 2,
        EnforcementLevel::E3 => 3,
        EnforcementLevel::E4 => 4,
        EnforcementLevel::E5 => 5,
    }
}

fn min_enf_rank(e: &ProfileSpec_MinEnforcementLevel) -> u8 {
    match e {
        ProfileSpec_MinEnforcementLevel::E0 => 0,
        ProfileSpec_MinEnforcementLevel::E1 => 1,
        ProfileSpec_MinEnforcementLevel::E2 => 2,
        ProfileSpec_MinEnforcementLevel::E3 => 3,
        ProfileSpec_MinEnforcementLevel::E4 => 4,
        ProfileSpec_MinEnforcementLevel::E5 => 5,
    }
}

fn proof_rank(p: &ProofLevel) -> u8 {
    match p {
        ProofLevel::L0 => 0,
        ProofLevel::L1 => 1,
        ProofLevel::L2 => 2,
        ProofLevel::L3 => 3,
        ProofLevel::L4 => 4,
        ProofLevel::L5 => 5,
    }
}

fn enf_label(e: &EnforcementLevel) -> &'static str {
    match e {
        EnforcementLevel::E0 => "E0",
        EnforcementLevel::E1 => "E1",
        EnforcementLevel::E2 => "E2",
        EnforcementLevel::E3 => "E3",
        EnforcementLevel::E4 => "E4",
        EnforcementLevel::E5 => "E5",
    }
}

fn min_enf_label(e: &ProfileSpec_MinEnforcementLevel) -> &'static str {
    match e {
        ProfileSpec_MinEnforcementLevel::E0 => "E0",
        ProfileSpec_MinEnforcementLevel::E1 => "E1",
        ProfileSpec_MinEnforcementLevel::E2 => "E2",
        ProfileSpec_MinEnforcementLevel::E3 => "E3",
        ProfileSpec_MinEnforcementLevel::E4 => "E4",
        ProfileSpec_MinEnforcementLevel::E5 => "E5",
    }
}

fn proof_label(p: &ProofLevel) -> &'static str {
    match p {
        ProofLevel::L0 => "L0",
        ProofLevel::L1 => "L1",
        ProofLevel::L2 => "L2",
        ProofLevel::L3 => "L3",
        ProofLevel::L4 => "L4",
        ProofLevel::L5 => "L5",
    }
}

fn anchor_id(a: &ProfileSpec_RequiredAnchors_Item) -> &'static str {
    match a {
        ProfileSpec_RequiredAnchors_Item::Rfc6962 => "rfc6962",
        ProfileSpec_RequiredAnchors_Item::Sigstore => "sigstore",
        ProfileSpec_RequiredAnchors_Item::Rfc3161 => "rfc3161",
        ProfileSpec_RequiredAnchors_Item::Memory => "memory",
        ProfileSpec_RequiredAnchors_Item::Custom => "custom",
    }
}

pub fn select_profile(spec: &ProfileSpec, gate: &ProfileFeatureGate) -> ProfileVerdict {
    let mut failures = Vec::new();
    let mut warnings = Vec::new();

    for m in &spec.must {
        if !gate.features.contains(&m.id) {
            failures.push(format!(
                "profile {} requires feature \"{}\" — missing",
                spec.profile_id, m.id
            ));
        }
    }

    if let Some(must_not) = &spec.must_not {
        for n in must_not {
            if gate.features.contains(&n.id) {
                failures.push(format!(
                    "profile {} forbids feature \"{}\"",
                    spec.profile_id, n.id
                ));
            }
        }
    }

    for s in &spec.should {
        if !gate.features.contains(&s.id) {
            warnings.push(format!(
                "profile {} recommends feature \"{}\"",
                spec.profile_id, s.id
            ));
        }
    }

    if let Some(min) = &spec.min_enforcement_level {
        if enf_rank(&gate.enforcement_level) < min_enf_rank(min) {
            failures.push(format!(
                "profile {} requires EnforcementLevel ≥ {}, daemon at {}",
                spec.profile_id,
                min_enf_label(min),
                enf_label(&gate.enforcement_level)
            ));
        }
    }

    if let Some(min) = &spec.min_proof_level {
        if proof_rank(&gate.proof_level_floor) < proof_rank(min) {
            failures.push(format!(
                "profile {} requires proof level floor ≥ {}, daemon at {}",
                spec.profile_id,
                proof_label(min),
                proof_label(&gate.proof_level_floor)
            ));
        }
    }

    if let Some(bridges) = &spec.required_bridges {
        for b in bridges {
            if !gate.bridges.contains(b) {
                failures.push(format!(
                    "profile {} requires bridge {} — missing",
                    spec.profile_id, b
                ));
            }
        }
    }

    if let Some(anchors) = &spec.required_anchors {
        for a in anchors {
            let id = anchor_id(a);
            if !gate.anchors.contains(id) {
                failures.push(format!(
                    "profile {} requires anchor {} — missing",
                    spec.profile_id, id
                ));
            }
        }
    }

    ProfileVerdict {
        ok: failures.is_empty(),
        profile: spec.profile_id.clone(),
        failures,
        warnings,
    }
}

fn feature(id: &str) -> Feature {
    Feature {
        id: id.to_string(),
        description: None,
        spec_ref: None,
    }
}

/// The four built-in conformance profiles. Mirrors `BUILTIN_PROFILES` in
/// `tools/tf-types-ts/src/core/profile.ts`.
pub fn builtin_profiles() -> Vec<ProfileSpec> {
    vec![
        ProfileSpec {
            profile_version: ProfileSpec_ProfileVersion::V1,
            profile_id: "tf-home-compatible".into(),
            label: "TrustForge home / personal-network profile".into(),
            description: None,
            must: vec![
                feature("agent-contract"),
                feature("proof-log"),
                feature("ed25519"),
                feature("vault"),
            ],
            should: vec![feature("webauthn"), feature("shadow-mode")],
            must_not: None,
            min_enforcement_level: Some(ProfileSpec_MinEnforcementLevel::E3),
            min_proof_level: Some(ProofLevel::L1),
            required_bridges: None,
            required_anchors: None,
        },
        ProfileSpec {
            profile_version: ProfileSpec_ProfileVersion::V1,
            profile_id: "tf-enterprise-compatible".into(),
            label: "TrustForge enterprise profile".into(),
            description: None,
            must: vec![
                feature("policy-engine"),
                feature("quorum-collector"),
                feature("continuous-reauth"),
                feature("transparency-anchor.any"),
                feature("federation"),
                feature("webauthn"),
                feature("agent-contract"),
            ],
            should: vec![feature("shadow-mode"), feature("hybrid-pq")],
            must_not: None,
            min_enforcement_level: Some(ProfileSpec_MinEnforcementLevel::E4),
            min_proof_level: Some(ProofLevel::L2),
            required_bridges: Some(vec![
                "webauthn".into(),
                "oauth".into(),
                "spiffe".into(),
            ]),
            required_anchors: Some(vec![ProfileSpec_RequiredAnchors_Item::Rfc6962]),
        },
        ProfileSpec {
            profile_version: ProfileSpec_ProfileVersion::V1,
            profile_id: "tf-constrained-compatible".into(),
            label: "TrustForge constrained / LoRa / offline profile".into(),
            description: None,
            must: vec![
                feature("packet-mode"),
                feature("fragment-reassembly"),
                feature("offline-revocation-list"),
                feature("emergency-authority"),
            ],
            should: vec![feature("cbor-encoding"), feature("deflate-compression")],
            must_not: Some(vec![
                feature("transport.websocket-only"),
                feature("transparency-anchor.always-online"),
            ]),
            min_enforcement_level: Some(ProfileSpec_MinEnforcementLevel::E3),
            min_proof_level: Some(ProofLevel::L1),
            required_bridges: None,
            required_anchors: None,
        },
        ProfileSpec {
            profile_version: ProfileSpec_ProfileVersion::V1,
            profile_id: "tf-compliance-evidence-compatible".into(),
            label: "TrustForge compliance / legal-evidence profile".into(),
            description: None,
            must: vec![
                feature("policy-engine"),
                feature("quorum-collector"),
                feature("signed-log-events"),
                feature("evidence-bundle"),
                feature("l4-encrypted-bundle"),
                feature("l5-rfc3161-anchor"),
                feature("continuous-reauth"),
            ],
            should: vec![feature("redaction"), feature("federation")],
            must_not: None,
            min_enforcement_level: Some(ProfileSpec_MinEnforcementLevel::E4),
            min_proof_level: Some(ProofLevel::L3),
            required_bridges: None,
            required_anchors: Some(vec![
                ProfileSpec_RequiredAnchors_Item::Rfc6962,
                ProfileSpec_RequiredAnchors_Item::Rfc3161,
            ]),
        },
    ]
}

/// Lookup a built-in profile by id.
pub fn builtin_profile(id: &str) -> Option<ProfileSpec> {
    builtin_profiles().into_iter().find(|p| p.profile_id == id)
}
