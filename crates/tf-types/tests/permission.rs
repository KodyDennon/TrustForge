//! Rust permission negotiation tests — mirror of TS suite.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde_json::json;
use tf_types::permission::{
    permission_grant_signing_bytes, provenance_from_request, sign_permission_grant,
    verify_permission_grant, PermissionGrant, PermissionRequest,
};

fn keypair() -> (SigningKey, [u8; 32]) {
    let s = SigningKey::generate(&mut OsRng);
    let pk = s.verifying_key().to_bytes();
    (s, pk)
}

fn make_request() -> PermissionRequest {
    PermissionRequest {
        request_version: "1".into(),
        id: "pr-1".into(),
        agent: "tf:actor:agent:example.com/code-helper".into(),
        instance: None,
        human: Some("tf:actor:human:example.com/alice".into()),
        model: Some("anthropic:claude-opus-4-7".into()),
        tool: Some("shell.exec".into()),
        action: "shell.exec".into(),
        target: Some("/usr/bin/ls -la".into()),
        risk: Some("R3".into()),
        danger_tags: Some(vec!["destructive".into(), "security-sensitive".into()]),
        duration_seconds: Some(300),
        reason: "list /usr".into(),
        proof_level_offered: Some("L3".into()),
        requested_at: "2026-04-24T13:00:00Z".into(),
        context: None,
    }
}

#[test]
fn provenance_from_request_carries_full_chain() {
    let req = make_request();
    let p = provenance_from_request(&req);
    assert_eq!(p.human.as_deref(), Some("tf:actor:human:example.com/alice"));
    assert_eq!(
        p.agent.as_deref(),
        Some("tf:actor:agent:example.com/code-helper")
    );
    assert_eq!(p.model.as_deref(), Some("anthropic:claude-opus-4-7"));
    assert_eq!(p.requested_action.as_deref(), Some("shell.exec"));
}

#[test]
fn signed_grant_round_trips() {
    let (signing, public) = keypair();
    let req = make_request();
    let priv_bytes = signing.to_bytes();
    let grant = sign_permission_grant(
        &req,
        "allow",
        "tf:actor:service:example.com/tf-daemon",
        &priv_bytes,
        Some(json!({ "name": "shell.exec", "risk": "R3" })),
        None,
        None,
        None,
        None,
        None,
        Some("2026-04-24T12:00:00Z".into()),
        Some("2030-01-01T00:00:00Z".into()),
    );
    let result = verify_permission_grant(&grant, &public, Some(&req), None);
    assert!(result.ok, "expected ok, got {:?}", result.reason);
}

#[test]
fn tampered_decision_fails_verification() {
    let (signing, public) = keypair();
    let req = make_request();
    let priv_bytes = signing.to_bytes();
    let mut grant = sign_permission_grant(
        &req,
        "allow",
        "tf:actor:service:example.com/tf-daemon",
        &priv_bytes,
        None,
        None,
        None,
        None,
        None,
        None,
        Some("2026-04-24T12:00:00Z".into()),
        Some("2030-01-01T00:00:00Z".into()),
    );
    grant.decision = "deny".into();
    let result = verify_permission_grant(&grant, &public, Some(&req), None);
    assert!(!result.ok);
}

#[test]
fn expired_grant_is_rejected() {
    let (signing, public) = keypair();
    let req = make_request();
    let priv_bytes = signing.to_bytes();
    let grant = sign_permission_grant(
        &req,
        "allow",
        "tf:actor:service:example.com/tf-daemon",
        &priv_bytes,
        None,
        None,
        None,
        None,
        None,
        None,
        Some("2026-04-23T00:00:00Z".into()),
        Some("2026-04-23T01:00:00Z".into()),
    );
    let result = verify_permission_grant(&grant, &public, Some(&req), Some("2026-04-25T00:00:00Z"));
    assert!(!result.ok);
    assert!(result.reason.unwrap_or_default().contains("window"));
}

#[test]
fn signing_bytes_are_stable() {
    let (signing, _) = keypair();
    let req = make_request();
    let priv_bytes = signing.to_bytes();
    let grant = sign_permission_grant(
        &req,
        "allow",
        "tf:actor:service:example.com/tf-daemon",
        &priv_bytes,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    let g2: PermissionGrant = grant.clone();
    assert_eq!(
        permission_grant_signing_bytes(&grant),
        permission_grant_signing_bytes(&g2)
    );
}
