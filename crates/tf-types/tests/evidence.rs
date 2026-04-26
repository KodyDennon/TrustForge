//! Rust compliance-evidence tests — mirror of TS suite.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde_json::json;
use tf_types::evidence::{
    assemble_evidence_bundle, evidence_signing_bytes, verify_evidence_bundle, AssembleArgs,
};

fn keypair() -> (SigningKey, [u8; 32]) {
    let s = SigningKey::generate(&mut OsRng);
    let pk = s.verifying_key().to_bytes();
    (s, pk)
}

fn ev(id: &str, ts: &str, type_: &str, actor: &str) -> serde_json::Value {
    json!({
        "event_version": "1",
        "id": id,
        "type": type_,
        "actor_id": actor,
        "timestamp": ts,
        "level": "L3",
        "signature": { "algorithm": "ed25519", "signer": actor, "signature": "AAAA" }
    })
}

#[test]
fn assemble_and_verify_round_trip() {
    let (signing, public) = keypair();
    let priv_bytes = signing.to_bytes();
    let events = vec![
        ev(
            "ev-1",
            "2026-04-24T12:01:00Z",
            "rpc.call",
            "tf:actor:agent:example.com/x",
        ),
        ev(
            "ev-2",
            "2026-04-24T12:02:00Z",
            "approval.approve",
            "tf:actor:human:example.com/alice",
        ),
    ];
    let r = assemble_evidence_bundle(
        &events,
        AssembleArgs {
            bundle_id: "i".into(),
            trust_domain: "example.com".into(),
            label: "test".into(),
            started_at: "2026-04-24T12:00:00Z".into(),
            ended_at: Some("2026-04-24T13:00:00Z".into()),
            issuer: "tf:actor:service:example.com/tf-daemon".into(),
            private_key: priv_bytes,
            ..Default::default()
        },
    )
    .expect("assemble");
    assert_eq!(r.bundle.events.len(), 2);
    assert_eq!(r.bundle.actors.as_ref().unwrap().len(), 2);
    let v = verify_evidence_bundle(&r.bundle, &public);
    assert!(v.outer_signature_ok);
}

#[test]
fn filter_by_actor_and_event_type_pattern() {
    let (signing, _) = keypair();
    let priv_bytes = signing.to_bytes();
    let events = vec![
        ev(
            "ev-1",
            "2026-04-24T12:01:00Z",
            "rpc.call",
            "tf:actor:agent:example.com/x",
        ),
        ev(
            "ev-2",
            "2026-04-24T12:02:00Z",
            "approval.approve",
            "tf:actor:human:example.com/alice",
        ),
        ev(
            "ev-3",
            "2026-04-24T12:03:00Z",
            "approval.deny",
            "tf:actor:human:example.com/alice",
        ),
    ];
    let r = assemble_evidence_bundle(
        &events,
        AssembleArgs {
            bundle_id: "i".into(),
            trust_domain: "example.com".into(),
            label: "filtered".into(),
            started_at: "2026-04-24T12:00:00Z".into(),
            ended_at: Some("2026-04-24T13:00:00Z".into()),
            actor_filter: Some(vec!["tf:actor:human:example.com/alice".into()]),
            event_type_pattern: Some("^approval\\.".into()),
            issuer: "tf:actor:service:example.com/tf-daemon".into(),
            private_key: priv_bytes,
            ..Default::default()
        },
    )
    .expect("assemble");
    assert_eq!(r.bundle.events.len(), 2);
}

#[test]
fn empty_filtered_set_errors() {
    let (signing, _) = keypair();
    let priv_bytes = signing.to_bytes();
    let events = vec![ev(
        "ev-1",
        "2026-04-24T12:01:00Z",
        "rpc.call",
        "tf:actor:agent:example.com/x",
    )];
    let r = assemble_evidence_bundle(
        &events,
        AssembleArgs {
            bundle_id: "i".into(),
            trust_domain: "example.com".into(),
            label: "empty".into(),
            started_at: "2026-04-24T13:00:00Z".into(),
            ended_at: Some("2026-04-24T14:00:00Z".into()),
            issuer: "tf:actor:service:example.com/tf-daemon".into(),
            private_key: priv_bytes,
            ..Default::default()
        },
    );
    assert!(r.is_err());
}

#[test]
fn signing_bytes_is_stable() {
    let (signing, _) = keypair();
    let priv_bytes = signing.to_bytes();
    let events = vec![ev(
        "ev-1",
        "2026-04-24T12:01:00Z",
        "rpc.call",
        "tf:actor:agent:example.com/x",
    )];
    let r = assemble_evidence_bundle(
        &events,
        AssembleArgs {
            bundle_id: "i".into(),
            trust_domain: "example.com".into(),
            label: "stable".into(),
            started_at: "2026-04-24T12:00:00Z".into(),
            ended_at: Some("2026-04-24T13:00:00Z".into()),
            issuer: "tf:actor:service:example.com/tf-daemon".into(),
            private_key: priv_bytes,
            ..Default::default()
        },
    )
    .unwrap();
    let a = evidence_signing_bytes(&r.bundle);
    let b = evidence_signing_bytes(&r.bundle.clone());
    assert_eq!(a, b);
}

#[test]
fn verify_rejects_tampered_label() {
    let (signing, public) = keypair();
    let priv_bytes = signing.to_bytes();
    let events = vec![ev(
        "ev-1",
        "2026-04-24T12:01:00Z",
        "rpc.call",
        "tf:actor:agent:example.com/x",
    )];
    let mut r = assemble_evidence_bundle(
        &events,
        AssembleArgs {
            bundle_id: "i".into(),
            trust_domain: "example.com".into(),
            label: "original".into(),
            started_at: "2026-04-24T12:00:00Z".into(),
            ended_at: Some("2026-04-24T13:00:00Z".into()),
            issuer: "tf:actor:service:example.com/tf-daemon".into(),
            private_key: priv_bytes,
            ..Default::default()
        },
    )
    .unwrap();
    r.bundle.incident.label = "tampered".into();
    let v = verify_evidence_bundle(&r.bundle, &public);
    assert!(!v.outer_signature_ok);
    assert!(!v.ok);
}
