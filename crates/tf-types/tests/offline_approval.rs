//! Rust offline-signed approval packet tests — mirror of TS suite.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde_json::json;
use tf_types::offline_approval::{
    sign_offline_approval_packet, verify_offline_approval_packet,
};

fn make_keypair() -> (SigningKey, [u8; 32]) {
    let signing = SigningKey::generate(&mut OsRng);
    let public = signing.verifying_key().to_bytes();
    (signing, public)
}

fn request() -> serde_json::Value {
    json!({
        "request_version": "1",
        "id": "req-offline-1",
        "actor": "tf:actor:agent:example.com/code-helper",
        "action": "firmware.install",
        "reason": "ship firmware v3 to gateway",
        "created_at": "2026-04-24T12:00:00Z"
    })
}

#[test]
fn round_trips_approve_packet_with_valid_signature() {
    let (signing, public) = make_keypair();
    let priv_bytes = signing.to_bytes();
    let packet = sign_offline_approval_packet(
        request(),
        "approve",
        "tf:actor:human:example.com/alice",
        &priv_bytes,
        "usb",
        None,
    );
    let result = verify_offline_approval_packet(&packet, &public, None, None);
    assert!(result.ok, "expected ok, got {:?}", result.reason);
    let response = result.response.unwrap();
    assert_eq!(response.decision, "approve");
    let ceremony = result.ceremony.unwrap();
    assert_eq!(ceremony.kind, "offline-signed-packet");
    assert_eq!(ceremony.transport_hint, "usb");
}

#[test]
fn rejects_packet_with_wrong_signing_key() {
    let (signing, _) = make_keypair();
    let (_, other_public) = make_keypair();
    let priv_bytes = signing.to_bytes();
    let packet = sign_offline_approval_packet(
        request(),
        "approve",
        "tf:actor:human:example.com/alice",
        &priv_bytes,
        "qr-code",
        None,
    );
    let result = verify_offline_approval_packet(&packet, &other_public, None, None);
    assert!(!result.ok);
}

#[test]
fn rejects_packet_older_than_max_age() {
    let (signing, public) = make_keypair();
    let priv_bytes = signing.to_bytes();
    let packet = sign_offline_approval_packet(
        request(),
        "approve",
        "tf:actor:human:example.com/alice",
        &priv_bytes,
        "file-drop",
        Some("2026-04-23T00:00:00Z"),
    );
    let result = verify_offline_approval_packet(
        &packet,
        &public,
        Some("2026-04-25T00:00:00Z"),
        Some(3600),
    );
    assert!(!result.ok);
    assert!(result.reason.unwrap_or_default().contains("older than"));
}

#[test]
fn rejects_packet_whose_responder_differs_from_signer() {
    let (signing, public) = make_keypair();
    let priv_bytes = signing.to_bytes();
    let mut packet = sign_offline_approval_packet(
        request(),
        "approve",
        "tf:actor:human:example.com/alice",
        &priv_bytes,
        "usb",
        None,
    );
    packet.signature.signer = "tf:actor:human:example.com/mallory".into();
    let result = verify_offline_approval_packet(&packet, &public, None, None);
    assert!(!result.ok);
}

#[test]
fn rejects_tampered_request_body() {
    let (signing, public) = make_keypair();
    let priv_bytes = signing.to_bytes();
    let mut packet = sign_offline_approval_packet(
        request(),
        "deny",
        "tf:actor:human:example.com/alice",
        &priv_bytes,
        "manual",
        None,
    );
    packet.request = json!({
        "request_version": "1",
        "id": "req-offline-1",
        "actor": "tf:actor:agent:example.com/code-helper",
        "action": "shell.exec",
        "reason": "different",
        "created_at": "2026-04-24T12:00:00Z"
    });
    let result = verify_offline_approval_packet(&packet, &public, None, None);
    assert!(!result.ok);
}
