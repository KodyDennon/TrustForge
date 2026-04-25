//! Rust policy-engine parity tests. Mirrors the TS suite.

use serde_json::json;
use tf_types::guard::NegativeCapability;
use tf_types::policy_engine::{NativePolicyEngine, PolicyManifest, PolicyQuery, PolicyRule};

fn manifest() -> PolicyManifest {
    PolicyManifest {
        policy_version: "1".into(),
        trust_domain: "example.com".into(),
        engine_hint: Some("native".into()),
        rules: vec![
            PolicyRule {
                id: "deny.write.secrets".into(),
                effect: "deny".into(),
                action: Some("file.write".into()),
                action_pattern: None,
                subject_pattern: None,
                target_patterns: Some(vec!["secrets/**".into(), ".env".into()]),
                approval: None,
                proof_required: None,
                constraints: None,
                reason: Some("secrets are off-limits".into()),
            },
            PolicyRule {
                id: "escalate.payments".into(),
                effect: "escalate".into(),
                action: None,
                action_pattern: Some("^payment\\.".into()),
                subject_pattern: None,
                target_patterns: None,
                approval: Some("quorum".into()),
                proof_required: None,
                constraints: None,
                reason: Some("payments require human approval".into()),
            },
            PolicyRule {
                id: "log.read".into(),
                effect: "log_only".into(),
                action: Some("file.read".into()),
                action_pattern: None,
                subject_pattern: None,
                target_patterns: None,
                approval: None,
                proof_required: None,
                constraints: None,
                reason: Some("audited but not gated".into()),
            },
            PolicyRule {
                id: "allow.write.source".into(),
                effect: "allow".into(),
                action: Some("file.write".into()),
                action_pattern: None,
                subject_pattern: None,
                target_patterns: Some(vec!["src/**".into()]),
                approval: None,
                proof_required: None,
                constraints: None,
                reason: Some("writes to src/ are allowed".into()),
            },
        ],
        negative_capabilities: vec![NegativeCapability {
            name: "shell.exec".into(),
            target: None,
            reason: Some("shell is forbidden in this domain".into()),
            overrides: None,
        }],
        continuous_reevaluation: Some(tf_types::policy_engine::ContinuousReeval {
            triggers: vec!["revocation".into(), "session_rekey".into()],
        }),
        quorum_defaults: None,
    }
}

#[test]
fn negative_cap_beats_every_allow() {
    let engine = NativePolicyEngine::new(manifest());
    let d = engine.evaluate(&PolicyQuery {
        subject: "tf:actor:agent:example.com/code-helper".into(),
        action: "shell.exec".into(),
        target: Some("/bin/ls".into()),
        ..PolicyQuery::default()
    });
    assert_eq!(d.decision, "deny");
    assert!(d.reason.unwrap_or_default().contains("shell is forbidden"));
}

#[test]
fn deny_wins_over_allow_below_it() {
    let engine = NativePolicyEngine::new(manifest());
    let d = engine.evaluate(&PolicyQuery {
        subject: "tf:actor:agent:example.com/code-helper".into(),
        action: "file.write".into(),
        target: Some("secrets/master.key".into()),
        ..PolicyQuery::default()
    });
    assert_eq!(d.decision, "deny");
    assert_eq!(d.rule_id.as_deref(), Some("deny.write.secrets"));
}

#[test]
fn allow_matches_when_target_glob_holds() {
    let engine = NativePolicyEngine::new(manifest());
    let d = engine.evaluate(&PolicyQuery {
        subject: "tf:actor:agent:example.com/code-helper".into(),
        action: "file.write".into(),
        target: Some("src/main.ts".into()),
        ..PolicyQuery::default()
    });
    assert_eq!(d.decision, "allow");
    assert_eq!(d.rule_id.as_deref(), Some("allow.write.source"));
}

#[test]
fn escalate_with_quorum_becomes_escalate_decision() {
    let engine = NativePolicyEngine::new(manifest());
    let d = engine.evaluate(&PolicyQuery {
        subject: "tf:actor:agent:example.com/code-helper".into(),
        action: "payment.charge".into(),
        target: Some("vendor:42".into()),
        ..PolicyQuery::default()
    });
    assert_eq!(d.decision, "escalate");
    assert_eq!(d.approval.as_deref(), Some("quorum"));
}

#[test]
fn log_only_rule_produces_log_only_decision() {
    let engine = NativePolicyEngine::new(manifest());
    let d = engine.evaluate(&PolicyQuery {
        subject: "tf:actor:agent:example.com/code-helper".into(),
        action: "file.read".into(),
        target: Some("any.txt".into()),
        ..PolicyQuery::default()
    });
    assert_eq!(d.decision, "log-only");
    assert_eq!(d.rule_id.as_deref(), Some("log.read"));
}

#[test]
fn default_deny_when_no_rule_matches() {
    let engine = NativePolicyEngine::new(manifest());
    let d = engine.evaluate(&PolicyQuery {
        subject: "tf:actor:agent:example.com/code-helper".into(),
        action: "kernel.module.load".into(),
        target: Some("snake-oil.ko".into()),
        ..PolicyQuery::default()
    });
    assert_eq!(d.decision, "deny");
    assert!(d.rule_id.is_none());
    assert!(d.reason.unwrap_or_default().contains("default deny"));
}

#[test]
fn manifest_hash_is_present() {
    let engine = NativePolicyEngine::new(manifest());
    let d = engine.evaluate(&PolicyQuery {
        subject: "tf:actor:agent:example.com/code-helper".into(),
        action: "file.read".into(),
        ..PolicyQuery::default()
    });
    let hash = d.policy_manifest_hash.unwrap();
    assert!(hash.starts_with("sha256-"));
    assert_eq!(hash.len(), 7 + 64);
}

#[test]
fn continuous_triggers_exposed() {
    let engine = NativePolicyEngine::new(manifest());
    let mut t = engine.continuous_triggers();
    t.sort();
    assert_eq!(t, vec!["revocation", "session_rekey"]);
}

#[test]
fn explicit_negative_caps_in_query_override_rules() {
    let engine = NativePolicyEngine::new(manifest());
    let d = engine.evaluate(&PolicyQuery {
        subject: "tf:actor:agent:example.com/code-helper".into(),
        action: "file.write".into(),
        target: Some("src/main.ts".into()),
        negative_capabilities: vec![NegativeCapability {
            name: "file.write".into(),
            target: None,
            reason: Some("frozen branch".into()),
            overrides: None,
        }],
        ..PolicyQuery::default()
    });
    assert_eq!(d.decision, "deny");
    assert_eq!(d.reason.as_deref(), Some("frozen branch"));
    let _ = json!({}); // ensure serde_json import is exercised
}
