//! Cedar policy engine fixtures.
//!
//! 8 vectors covering: allow, deny (forbid), deny-overrides-allow,
//! allow with conditions on attributes, allow with constraints
//! (action set), missing entities (safe deny), malformed policy
//! (constructor error), realistic role-based policy.

use std::collections::HashMap;

use serde_json::json;

use tf_cedar::{CedarError, CedarPolicyEngine};
use tf_types::policy_engine::PolicyQuery;

fn query(subject: &str, action: &str, target: Option<&str>) -> PolicyQuery {
    PolicyQuery {
        subject: subject.into(),
        instance: None,
        action: action.into(),
        target: target.map(|t| t.into()),
        context: HashMap::new(),
        negative_capabilities: vec![],
        enforcement_level: None,
        now: Some("2026-04-25T00:00:00Z".into()),
    }
}

#[test]
fn allow_simple_permit() {
    let policy = r#"
        permit(
            principal == User::"alice",
            action == Action::"read",
            resource == Photo::"vacation.jpg"
        );
    "#;
    let engine = CedarPolicyEngine::new(policy, "[]").expect("engine");
    let q = query(r#"User::"alice""#, r#"Action::"read""#, Some(r#"Photo::"vacation.jpg""#));
    let d = engine.evaluate(&q);
    assert_eq!(d.decision, "allow");
    assert!(d.rule_id.is_some(), "allow should carry the policy id");
    assert_eq!(d.policy_engine, "cedar");
}

#[test]
fn deny_via_forbid() {
    let policy = r#"
        permit(principal, action, resource);
        forbid(
            principal,
            action == Action::"delete",
            resource
        );
    "#;
    let engine = CedarPolicyEngine::new(policy, "[]").expect("engine");
    let q = query(r#"User::"alice""#, r#"Action::"delete""#, Some(r#"Photo::"x""#));
    let d = engine.evaluate(&q);
    assert_eq!(d.decision, "deny");
    assert!(
        d.reason.as_deref().unwrap_or("").contains("forbid"),
        "reason should mention forbid: {:?}",
        d.reason
    );
}

#[test]
fn deny_overrides_allow_when_both_match() {
    // Both a permit and forbid match — Cedar's semantics say forbid wins.
    let policy = r#"
        permit(
            principal == User::"alice",
            action == Action::"read",
            resource
        );
        forbid(
            principal == User::"alice",
            action == Action::"read",
            resource
        );
    "#;
    let engine = CedarPolicyEngine::new(policy, "[]").expect("engine");
    let q = query(r#"User::"alice""#, r#"Action::"read""#, Some(r#"Photo::"x""#));
    let d = engine.evaluate(&q);
    assert_eq!(d.decision, "deny", "forbid must override permit");
}

#[test]
fn allow_with_attribute_condition() {
    let policy = r#"
        permit(
            principal,
            action == Action::"read",
            resource
        ) when {
            resource has owner && resource.owner == "alice"
        };
    "#;
    let entities = r#"[
        {"uid": {"type": "Photo", "id": "p1"}, "attrs": {"owner": "alice"}, "parents": []},
        {"uid": {"type": "Photo", "id": "p2"}, "attrs": {"owner": "bob"}, "parents": []}
    ]"#;
    let engine = CedarPolicyEngine::new(policy, entities).expect("engine");
    let allow = engine.evaluate(&query(r#"User::"alice""#, r#"Action::"read""#, Some(r#"Photo::"p1""#)));
    assert_eq!(allow.decision, "allow");
    let deny = engine.evaluate(&query(r#"User::"alice""#, r#"Action::"read""#, Some(r#"Photo::"p2""#)));
    assert_eq!(deny.decision, "deny", "alice does not own p2");
}

#[test]
fn allow_with_action_in_set_constraint() {
    // The "constraint" being tested is the `action in [...]` Cedar form.
    let policy = r#"
        permit(
            principal,
            action in [Action::"read", Action::"list"],
            resource
        );
    "#;
    let engine = CedarPolicyEngine::new(policy, "[]").expect("engine");
    let read = engine.evaluate(&query(r#"User::"alice""#, r#"Action::"read""#, Some(r#"Photo::"x""#)));
    assert_eq!(read.decision, "allow");
    let list = engine.evaluate(&query(r#"User::"alice""#, r#"Action::"list""#, Some(r#"Photo::"x""#)));
    assert_eq!(list.decision, "allow");
    let write = engine.evaluate(&query(r#"User::"alice""#, r#"Action::"write""#, Some(r#"Photo::"x""#)));
    assert_eq!(write.decision, "deny", "write is not in the action set");
}

#[test]
fn missing_entity_results_in_safe_deny() {
    // Policy references resource attributes the entities don't carry —
    // Cedar treats the attribute access as an evaluation error, which
    // collapses the rule. We must NOT panic; the result must be deny.
    let policy = r#"
        permit(
            principal,
            action == Action::"read",
            resource
        ) when {
            resource.classified == false
        };
    "#;
    // No entities at all: resource.classified can't resolve.
    let engine = CedarPolicyEngine::new(policy, "[]").expect("engine");
    let d = engine.evaluate(&query(r#"User::"alice""#, r#"Action::"read""#, Some(r#"Photo::"unknown""#)));
    assert_eq!(d.decision, "deny", "missing attributes must safe-deny");
}

#[test]
fn malformed_policy_returns_constructor_error() {
    let policy = "this is not cedar";
    match CedarPolicyEngine::new(policy, "[]") {
        Err(CedarError::Policy(_)) => {}
        Err(other) => panic!("expected CedarError::Policy, got {:?}", other),
        Ok(_) => panic!("malformed policy must fail to compile"),
    }
}

#[test]
fn realistic_role_based_policy() {
    let policy = r#"
        // Admins can do anything.
        permit(
            principal in Role::"admin",
            action,
            resource
        );
        // Reviewers can only read.
        permit(
            principal in Role::"reviewer",
            action == Action::"read",
            resource
        );
    "#;
    let entities = json!([
        {"uid": {"type": "Role", "id": "admin"}, "attrs": {}, "parents": []},
        {"uid": {"type": "Role", "id": "reviewer"}, "attrs": {}, "parents": []},
        {"uid": {"type": "User", "id": "alice"}, "attrs": {}, "parents": [{"type": "Role", "id": "admin"}]},
        {"uid": {"type": "User", "id": "bob"}, "attrs": {}, "parents": [{"type": "Role", "id": "reviewer"}]},
        {"uid": {"type": "User", "id": "carol"}, "attrs": {}, "parents": []}
    ])
    .to_string();
    let engine = CedarPolicyEngine::new(policy, &entities).expect("engine");

    // Alice (admin) can write.
    let alice_write = engine.evaluate(&query(
        r#"User::"alice""#,
        r#"Action::"write""#,
        Some(r#"Photo::"x""#),
    ));
    assert_eq!(alice_write.decision, "allow", "admin can write");

    // Bob (reviewer) can read but not write.
    let bob_read = engine.evaluate(&query(
        r#"User::"bob""#,
        r#"Action::"read""#,
        Some(r#"Photo::"x""#),
    ));
    assert_eq!(bob_read.decision, "allow", "reviewer can read");
    let bob_write = engine.evaluate(&query(
        r#"User::"bob""#,
        r#"Action::"write""#,
        Some(r#"Photo::"x""#),
    ));
    assert_eq!(bob_write.decision, "deny", "reviewer cannot write");

    // Carol has no role — nothing matches.
    let carol_read = engine.evaluate(&query(
        r#"User::"carol""#,
        r#"Action::"read""#,
        Some(r#"Photo::"x""#),
    ));
    assert_eq!(carol_read.decision, "deny", "no role -> default deny");
}
