//! Rust quorum collector tests — mirror of TS suite.

use tf_types::quorum::{QuorumApprovalCollector, QuorumConfig, QuorumSignature};

fn config() -> QuorumConfig {
    QuorumConfig {
        min_approvers: 2,
        of: vec![
            "tf:actor:human:example.com/alice".into(),
            "tf:actor:human:example.com/bob".into(),
            "tf:actor:human:example.com/carol".into(),
        ],
    }
}

fn sig(s: &str) -> QuorumSignature {
    QuorumSignature {
        algorithm: "ed25519".into(),
        signer: String::new(),
        signature: s.into(),
    }
}

#[test]
fn approves_once_min_approvers_signs() {
    let collector = QuorumApprovalCollector::new(config()).unwrap();
    let handle = collector.push("req-1", "2026-04-24T12:00:00Z");
    assert!(handle.respond_as("tf:actor:human:example.com/alice", "approve", sig("AAAA")));
    assert!(handle.respond_as("tf:actor:human:example.com/bob", "approve", sig("BBBB")));
    let outcome = handle.outcome().expect("resolved");
    assert_eq!(outcome.decision, "approve");
    assert_eq!(outcome.approvers.len(), 2);
    assert_eq!(outcome.ceremony.kind, "quorum");
    assert_eq!(outcome.ceremony.signatures.len(), 2);
}

#[test]
fn denies_when_eligible_set_fails_to_reach_quorum() {
    let cfg = QuorumConfig {
        min_approvers: 2,
        of: vec![
            "tf:actor:human:example.com/alice".into(),
            "tf:actor:human:example.com/bob".into(),
        ],
    };
    let collector = QuorumApprovalCollector::new(cfg).unwrap();
    let handle = collector.push("req-2", "2026-04-24T12:00:00Z");
    handle.respond_as("tf:actor:human:example.com/alice", "deny", sig("X"));
    handle.respond_as("tf:actor:human:example.com/bob", "approve", sig("Y"));
    let outcome = handle.outcome().expect("resolved");
    assert_eq!(outcome.decision, "deny");
}

#[test]
fn ignores_responses_from_non_eligible_actors() {
    let collector = QuorumApprovalCollector::new(config()).unwrap();
    let handle = collector.push("req-3", "2026-04-24T12:00:00Z");
    let accepted = handle.respond_as("tf:actor:human:example.com/mallory", "approve", sig("X"));
    assert!(!accepted);
}

#[test]
fn rejects_misconfigured_quorum() {
    let bad = QuorumConfig {
        min_approvers: 3,
        of: vec![
            "tf:actor:human:example.com/a".into(),
            "tf:actor:human:example.com/b".into(),
        ],
    };
    assert!(QuorumApprovalCollector::new(bad).is_err());
    let zero = QuorumConfig {
        min_approvers: 0,
        of: vec![
            "tf:actor:human:example.com/a".into(),
            "tf:actor:human:example.com/b".into(),
        ],
    };
    assert!(QuorumApprovalCollector::new(zero).is_err());
}

#[test]
fn ignores_duplicate_responses_from_same_actor() {
    let collector = QuorumApprovalCollector::new(config()).unwrap();
    let handle = collector.push("req-4", "2026-04-24T12:00:00Z");
    assert!(handle.respond_as("tf:actor:human:example.com/alice", "approve", sig("1")));
    assert!(!handle.respond_as("tf:actor:human:example.com/alice", "deny", sig("2")));
}
