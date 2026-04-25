//! Rust parity for `tools/tf-types-ts/tests/negative-capability.test.ts`.
//! Loads `conformance/negative-capability-vectors.yaml` and asserts that
//! every vector produces the expected GuardDecision.kind on the Rust side.

use std::fs;
use std::path::PathBuf;

use serde::Deserialize;
use serde_json::Value;

use tf_types::expiration::{check_window, is_expired, is_within_window, ExpirationVerdict, Window};
use tf_types::guard::{
    apply_enforcement_level, AgentGuard, EnforcementLevel, GuardDecision, GuardQuery,
    NegativeCapability,
};

#[derive(Deserialize)]
struct VectorFile {
    vectors: Vec<VectorEntry>,
}

#[derive(Deserialize)]
struct VectorEntry {
    name: String,
    contract: Value,
    #[serde(default)]
    negative_capabilities: Vec<NegCap>,
    #[serde(default)]
    enforcement_level: Option<String>,
    query: Query,
    expect: String,
}

#[derive(Deserialize)]
struct NegCap {
    name: String,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Deserialize)]
struct Query {
    action: String,
    #[serde(default)]
    target: Option<String>,
}

fn load_vectors() -> VectorFile {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("conformance")
        .join("negative-capability-vectors.yaml");
    let raw = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
    serde_yaml::from_str(&raw).expect("parse negative-capability-vectors.yaml")
}

#[test]
fn every_vector_matches() {
    let file = load_vectors();
    for v in file.vectors {
        let mut guard = AgentGuard::from_contract(&v.contract);
        let caps: Vec<NegativeCapability> = v
            .negative_capabilities
            .into_iter()
            .map(|n| NegativeCapability {
                name: n.name,
                target: n.target,
                reason: n.reason,
                overrides: None,
            })
            .collect();
        guard.set_negative_capabilities(caps);
        if let Some(level) = v.enforcement_level.as_deref() {
            guard.set_enforcement_level(
                EnforcementLevel::parse(level).expect("known enforcement level"),
            );
        }
        let decision = guard.check(&GuardQuery {
            actor: None,
            actor_claim: None,
            action: v.query.action,
            target: v.query.target,
        });
        assert_eq!(decision.kind(), v.expect, "vector {}", v.name);
    }
}

#[test]
fn e0_wraps_every_non_allow_as_log_only() {
    let denied = apply_enforcement_level(
        GuardDecision::Deny {
            reason: "blocked".into(),
            danger_tags: vec![],
        },
        EnforcementLevel::E0,
    );
    assert_eq!(denied.kind(), "log-only");

    let escalated = apply_enforcement_level(
        GuardDecision::Escalate {
            reason: "destructive".into(),
            danger_tags: vec!["destructive".into()],
        },
        EnforcementLevel::E0,
    );
    assert_eq!(escalated.kind(), "log-only");

    let approval = apply_enforcement_level(
        GuardDecision::ApprovalRequired {
            approval: "required".into(),
            reason: "x".into(),
            danger_tags: vec![],
        },
        EnforcementLevel::E0,
    );
    assert_eq!(approval.kind(), "log-only");

    let allow = apply_enforcement_level(
        GuardDecision::Allow { danger_tags: vec![] },
        EnforcementLevel::E0,
    );
    assert_eq!(allow.kind(), "allow");
}

#[test]
fn e1_warn_mode_turns_deny_into_allow_with_tag() {
    let adjusted = apply_enforcement_level(
        GuardDecision::Deny {
            reason: "no".into(),
            danger_tags: vec![],
        },
        EnforcementLevel::E1,
    );
    assert_eq!(adjusted.kind(), "allow");
    let tags = adjusted.danger_tags();
    assert!(tags.iter().any(|t| t == "warn"));
}

#[test]
fn e2_tags_proof_log_required() {
    let adjusted = apply_enforcement_level(
        GuardDecision::Allow { danger_tags: vec![] },
        EnforcementLevel::E2,
    );
    assert!(adjusted.danger_tags().iter().any(|t| t == "proof-log-required"));
}

#[test]
fn e3_escalates_allow_with_danger_tags() {
    let adjusted = apply_enforcement_level(
        GuardDecision::Allow {
            danger_tags: vec!["privacy".into()],
        },
        EnforcementLevel::E3,
    );
    assert_eq!(adjusted.kind(), "escalate");
}

#[test]
fn e4_is_identity() {
    let adjusted = apply_enforcement_level(
        GuardDecision::Allow { danger_tags: vec![] },
        EnforcementLevel::E4,
    );
    assert_eq!(adjusted.kind(), "allow");
}

#[test]
fn e5_fail_closed_blocks_escalations_and_tagged_allows() {
    let from_esc = apply_enforcement_level(
        GuardDecision::Escalate {
            reason: "destructive".into(),
            danger_tags: vec!["destructive".into()],
        },
        EnforcementLevel::E5,
    );
    assert_eq!(from_esc.kind(), "deny");

    let from_app = apply_enforcement_level(
        GuardDecision::ApprovalRequired {
            approval: "required".into(),
            reason: "x".into(),
            danger_tags: vec![],
        },
        EnforcementLevel::E5,
    );
    assert_eq!(from_app.kind(), "deny");

    let from_allow_tagged = apply_enforcement_level(
        GuardDecision::Allow {
            danger_tags: vec!["privacy".into()],
        },
        EnforcementLevel::E5,
    );
    assert_eq!(from_allow_tagged.kind(), "deny");
}

#[test]
fn check_window_inside_window_is_ok() {
    let w = Window {
        valid_from: Some("2026-01-01T00:00:00Z"),
        valid_until: Some("2026-12-31T23:59:59Z"),
        ..Window::default()
    };
    assert!(matches!(check_window(&w, "2026-04-24T12:00:00Z"), ExpirationVerdict::Ok));
}

#[test]
fn check_window_after_valid_until_is_expired() {
    let w = Window {
        valid_until: Some("2026-04-23T23:59:59Z"),
        ..Window::default()
    };
    let v = check_window(&w, "2026-04-24T00:00:00Z");
    assert!(matches!(v, ExpirationVerdict::Expired { .. }));
}

#[test]
fn check_window_before_valid_from_is_not_yet_valid() {
    let w = Window {
        valid_from: Some("2027-01-01T00:00:00Z"),
        ..Window::default()
    };
    assert!(matches!(
        check_window(&w, "2026-04-24T00:00:00Z"),
        ExpirationVerdict::NotYetValid { .. }
    ));
}

#[test]
fn check_window_uses_alternate_keys() {
    let w_expires = Window {
        expires_at: Some("2026-04-25T00:00:00Z"),
        ..Window::default()
    };
    assert!(is_within_window(&w_expires, "2026-04-24T00:00:00Z"));

    let w_not_after = Window {
        not_after: Some("2026-04-23T00:00:00Z"),
        ..Window::default()
    };
    assert!(is_expired(&w_not_after, "2026-04-24T00:00:00Z"));
}

#[test]
fn no_bounds_means_always_valid() {
    let w = Window::default();
    assert!(is_within_window(&w, "2026-04-24T00:00:00Z"));
    assert!(!is_expired(&w, "2026-04-24T00:00:00Z"));
}
