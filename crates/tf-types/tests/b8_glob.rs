//! B8 glob tests — Rust mirror of TS b8-guard-policy.test.ts
//! (the bits applicable to AgentGuard).

use serde_json::json;
use tf_types::guard::{AgentGuard, GuardQuery};

#[test]
fn question_mark_in_pattern_no_longer_matches_one_fewer_char() {
    let guard = AgentGuard::from_contract(&json!({
        "contract_version": "1",
        "spec_version": "TF-0006-draft",
        "project": "b8",
        "trust_domain": "example.com",
        "actions": [{
            "name": "fs.write",
            "risk": "R0",
            "approval": "none",
            "reversible": true,
            "deny_actors": ["tf:actor:user?"],
        }],
    }));
    let a = guard.check(&GuardQuery {
        actor: Some("tf:actor:user?".to_string()),
        actor_claim: None,
        action: "fs.write".to_string(),
        target: None,
    });
    let b = guard.check(&GuardQuery {
        actor: Some("tf:actor:use".to_string()),
        actor_claim: None,
        action: "fs.write".to_string(),
        target: None,
    });
    assert_eq!(a.kind(), "deny");
    assert_eq!(b.kind(), "allow");
}

#[test]
fn non_ascii_glob_pattern_matches_non_ascii_actor() {
    let guard = AgentGuard::from_contract(&json!({
        "contract_version": "1",
        "spec_version": "TF-0006-draft",
        "project": "b8",
        "trust_domain": "example.com",
        "actions": [{
            "name": "fs.write",
            "risk": "R0",
            "approval": "none",
            "reversible": true,
            "allow_actors": ["tf:actor:human:example.com/résumé"],
        }],
    }));
    let ok = guard.check(&GuardQuery {
        actor: Some("tf:actor:human:example.com/résumé".to_string()),
        actor_claim: None,
        action: "fs.write".to_string(),
        target: None,
    });
    assert_eq!(ok.kind(), "allow");
}
