//! Rego policy engine fixtures.
//!
//! 6 vectors covering: allow (boolean true), deny (boolean false / default),
//! complex conditional, role-based, missing input field (safe deny on
//! `default allow = false`), malformed policy (constructor error).

use std::collections::HashMap;

use tf_rego::{RegoError, RegoPolicyEngine};
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
fn allow_when_predicate_holds() {
    let policy = r#"
package trustforge

default allow = false

allow if {
    input.action == "read"
    input.subject == "alice"
}
"#;
    let engine = RegoPolicyEngine::new(policy).expect("engine");
    let d = engine.evaluate(&query("alice", "read", Some("doc1")));
    assert_eq!(d.decision, "allow");
    assert_eq!(d.policy_engine, "rego");
}

#[test]
fn deny_when_predicate_fails() {
    let policy = r#"
package trustforge

default allow = false

allow if {
    input.action == "read"
    input.subject == "alice"
}
"#;
    let engine = RegoPolicyEngine::new(policy).expect("engine");
    let d = engine.evaluate(&query("bob", "read", Some("doc1")));
    assert_eq!(d.decision, "deny");
}

#[test]
fn complex_conditional_with_rich_object() {
    // The richer `{decision, reason, rule_id}` shape is supported alongside
    // the plain boolean form. We point the engine at `data.trustforge.allow`
    // (the default) but the rule produces an object instead of a bool.
    let policy = r#"
package trustforge

default allow := {"decision": "deny", "reason": "default-deny"}

allow := {"decision": "allow", "reason": "alice can read docs", "rule_id": "rule.read.alice"} if {
    input.action == "read"
    input.subject == "alice"
    startswith(input.target, "doc")
}
"#;
    let engine = RegoPolicyEngine::new(policy).expect("engine");
    let allow = engine.evaluate(&query("alice", "read", Some("doc-42")));
    assert_eq!(allow.decision, "allow");
    assert_eq!(allow.rule_id.as_deref(), Some("rule.read.alice"));
    assert_eq!(allow.reason.as_deref(), Some("alice can read docs"));

    let deny = engine.evaluate(&query("alice", "read", Some("photo-1")));
    assert_eq!(deny.decision, "deny");
    assert_eq!(deny.reason.as_deref(), Some("default-deny"));
}

#[test]
fn role_based_allow() {
    let policy = r#"
package trustforge

default allow = false

# admins do anything
allow if {
    input.context.role == "admin"
}

# reviewers read only
allow if {
    input.context.role == "reviewer"
    input.action == "read"
}
"#;
    let engine = RegoPolicyEngine::new(policy).expect("engine");

    let mut admin_ctx = HashMap::new();
    admin_ctx.insert("role".to_string(), serde_json::json!("admin"));
    let admin_q = PolicyQuery {
        subject: "alice".into(),
        action: "write".into(),
        target: Some("doc".into()),
        context: admin_ctx,
        ..Default::default()
    };
    assert_eq!(engine.evaluate(&admin_q).decision, "allow");

    let mut rev_ctx = HashMap::new();
    rev_ctx.insert("role".to_string(), serde_json::json!("reviewer"));
    let rev_read = PolicyQuery {
        subject: "bob".into(),
        action: "read".into(),
        target: Some("doc".into()),
        context: rev_ctx.clone(),
        ..Default::default()
    };
    assert_eq!(engine.evaluate(&rev_read).decision, "allow");
    let rev_write = PolicyQuery {
        subject: "bob".into(),
        action: "write".into(),
        target: Some("doc".into()),
        context: rev_ctx,
        ..Default::default()
    };
    assert_eq!(engine.evaluate(&rev_write).decision, "deny");
}

#[test]
fn missing_input_field_safe_deny() {
    // Rule references `input.context.role`, which does not exist on a
    // bare query. Rego should produce false (because of `default allow = false`),
    // and we should NOT panic.
    let policy = r#"
package trustforge

default allow = false

allow if {
    input.context.role == "admin"
}
"#;
    let engine = RegoPolicyEngine::new(policy).expect("engine");
    let d = engine.evaluate(&query("nobody", "any", Some("anywhere")));
    assert_eq!(d.decision, "deny", "missing fields must safe-deny");
}

#[test]
fn malformed_policy_returns_constructor_error() {
    let policy = "this is not rego";
    match RegoPolicyEngine::new(policy) {
        Err(RegoError::Policy(_)) => {}
        Ok(_) => panic!("malformed policy must fail"),
    }
}

#[test]
fn partial_input_does_not_panic_and_safe_denies() {
    // Partial / sparse input — only a subject is supplied, several rule
    // branches reference nested context fields that aren't present. The
    // engine must (a) not panic, (b) collapse those branches to false,
    // and (c) the `default allow = false` must take effect.
    let policy = r#"
package trustforge

default allow = false

# admin escape hatch needs a rich context shape
allow if {
    input.context.role == "admin"
    input.context.tenant == "primary"
    input.action == "write"
}

# minimal-form allow that only requires a subject + action
allow if {
    input.subject == "trusted-bot"
    input.action == "read"
}
"#;
    let engine = RegoPolicyEngine::new(policy).expect("engine");

    // Sparse input: matches the second rule.
    let allow = engine.evaluate(&PolicyQuery {
        subject: "trusted-bot".into(),
        action: "read".into(),
        ..Default::default()
    });
    assert_eq!(allow.decision, "allow");

    // Sparse input: hits the admin branch but `context.tenant` missing →
    // safe deny, not a runtime error.
    let mut admin_ctx = HashMap::new();
    admin_ctx.insert("role".to_string(), serde_json::json!("admin"));
    let deny = engine.evaluate(&PolicyQuery {
        subject: "alice".into(),
        action: "write".into(),
        context: admin_ctx,
        ..Default::default()
    });
    assert_eq!(deny.decision, "deny");
}
