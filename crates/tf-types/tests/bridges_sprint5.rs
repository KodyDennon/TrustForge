//! Sprint-5 Rust bridge tests: DID, Matrix, Webhook, Service-Mesh.

use ed25519_dalek::SigningKey;
use ed25519_dalek::Signer;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use sha2::Sha256;
use tf_types::bridge_did::{ed25519_public_key_to_did_key, DidBridge, DidBridgeConfig};
use tf_types::bridge_matrix::{map_sender, MatrixBridge, MatrixBridgeConfig, MatrixEvent};
use tf_types::bridge_service_mesh::{ServiceMeshBridge, ServiceMeshBridgeConfig, XfccEntry};
use tf_types::bridge_webhook::{
    VerifyWebhookArgs, WebhookBridge, WebhookBridgeConfig, WebhookScheme,
};
use tf_types::bridges::Bridge;

type HmacSha256 = Hmac<Sha256>;

#[test]
fn did_key_resolves_and_projects() {
    let signing = SigningKey::generate(&mut OsRng);
    let pub_bytes = signing.verifying_key().to_bytes();
    let multibase = ed25519_public_key_to_did_key(&pub_bytes).unwrap();
    let did_url = format!("did:key:{}", multibase);
    let bridge = DidBridge::new(DidBridgeConfig {
        bridge_id: "tf-did".into(),
        trust_domain: "example.com".into(),
        allowed_methods: None,
    });
    let doc = bridge.resolve_did_key(&did_url).expect("resolve");
    assert_eq!(doc.id, did_url);
    let identity = bridge.accept(&doc).expect("accept");
    assert!(identity
        .actor_id
        .starts_with("tf:actor:human:example.com/"));
}

#[test]
fn did_method_allowlist_rejects_other_methods() {
    let bridge = DidBridge::new(DidBridgeConfig {
        bridge_id: "tf-did".into(),
        trust_domain: "example.com".into(),
        allowed_methods: Some(vec!["web".into()]),
    });
    let result = bridge.resolve_did_key("did:key:zinvalid");
    assert!(result.is_err());
}

#[test]
fn matrix_room_message_projects_to_proof_event() {
    let bridge = MatrixBridge::new(MatrixBridgeConfig {
        bridge_id: "tf-mx".into(),
        trust_domain: "example.com".into(),
        default_level: Some("L1".into()),
    });
    let projected = bridge
        .matrix_event_to_proof_event(&MatrixEvent {
            event_id: "$abc123".into(),
            room_id: "!room:example.com".into(),
            kind: "m.room.message".into(),
            sender: "@alice:example.com".into(),
            origin_server_ts: 1_745_496_000_000,
            content: serde_json::json!({ "body": "hi" }),
            state_key: None,
            signatures: None,
        })
        .expect("project");
    assert_eq!(projected["actor_id"], "tf:actor:human:example.com/alice");
    assert_eq!(projected["type"], "matrix.message");
}

#[test]
fn matrix_map_sender_rejects_non_matrix() {
    assert!(map_sender("not-a-matrix-sender").is_err());
}

#[test]
fn webhook_hmac_sha256_round_trip() {
    let secret = b"whsec_test".to_vec();
    let body = serde_json::to_vec(&serde_json::json!({"id":"evt_1"})).unwrap();
    let mut mac = HmacSha256::new_from_slice(&secret).unwrap();
    mac.update(&body);
    let sig: String = mac.finalize().into_bytes().iter().map(|b| format!("{:02x}", b)).collect();
    let bridge = WebhookBridge::new(WebhookBridgeConfig {
        bridge_id: "tf-wh".into(),
        trust_domain: "example.com".into(),
        vendor: "stripe".into(),
        scheme: WebhookScheme::HmacSha256,
        secret,
        max_age_seconds: None,
        default_risk: None,
    });
    let result = bridge
        .verify(VerifyWebhookArgs {
            body,
            signature_header: sig,
            timestamp_header: None,
            event_type: "charge.succeeded".into(),
            event_id: "evt_1".into(),
            received_at: None,
        })
        .expect("verify");
    assert_eq!(result.event["type"], "webhook.stripe.charge.succeeded");
}

#[test]
fn webhook_ed25519_verifies_signed_payload() {
    let signing = SigningKey::generate(&mut OsRng);
    let public = signing.verifying_key().to_bytes();
    let ts = "1745496000".to_string();
    let body = b"{}".to_vec();
    let mut payload = Vec::new();
    payload.extend_from_slice(ts.as_bytes());
    payload.push(b'.');
    payload.extend_from_slice(&body);
    let sig: ed25519_dalek::Signature = signing.sign(&payload);
    let sig_hex: String = sig.to_bytes().iter().map(|b| format!("{:02x}", b)).collect();
    let bridge = WebhookBridge::new(WebhookBridgeConfig {
        bridge_id: "tf-wh".into(),
        trust_domain: "example.com".into(),
        vendor: "discord".into(),
        scheme: WebhookScheme::Ed25519,
        secret: public.to_vec(),
        max_age_seconds: Some(60 * 60 * 24 * 365 * 10),
        default_risk: None,
    });
    let result = bridge
        .verify(VerifyWebhookArgs {
            body,
            signature_header: sig_hex,
            timestamp_header: Some(ts),
            event_type: "INTERACTION_CREATE".into(),
            event_id: "i-1".into(),
            received_at: None,
        })
        .expect("verify");
    assert!(result.event["type"].as_str().unwrap().contains("webhook.discord."));
}

#[test]
fn webhook_rejects_signature_mismatch() {
    let bridge = WebhookBridge::new(WebhookBridgeConfig {
        bridge_id: "tf-wh".into(),
        trust_domain: "example.com".into(),
        vendor: "vendor".into(),
        scheme: WebhookScheme::HmacSha256,
        secret: b"right".to_vec(),
        max_age_seconds: None,
        default_risk: None,
    });
    let result = bridge.verify(VerifyWebhookArgs {
        body: b"body".to_vec(),
        signature_header: "deadbeef".into(),
        timestamp_header: None,
        event_type: "x".into(),
        event_id: "y".into(),
        received_at: None,
    });
    assert!(result.is_err());
}

#[test]
fn service_mesh_envoy_xfcc_with_spiffe_uri() {
    let bridge = ServiceMeshBridge::new(ServiceMeshBridgeConfig {
        bridge_id: "tf-mesh".into(),
        trust_domain: "example.com".into(),
    });
    let identity = bridge
        .accept_envoy(&XfccEntry {
            uri: Some("spiffe://example.com/ns/foo/sa/bar".into()),
            by: Some("envoy".into()),
            hash: Some("abc".into()),
            subject: None,
        })
        .expect("envoy");
    assert_eq!(
        identity.actor_id,
        "tf:actor:service:example.com/ns/foo/sa/bar"
    );
}

#[test]
fn service_mesh_linkerd_parses_client_id() {
    let bridge = ServiceMeshBridge::new(ServiceMeshBridgeConfig {
        bridge_id: "tf-mesh".into(),
        trust_domain: "example.com".into(),
    });
    let identity = bridge
        .accept_linkerd("myapp.production.serviceaccount.identity.cluster1.cluster.local")
        .expect("linkerd");
    assert_eq!(
        identity.actor_id,
        "tf:actor:service:cluster1/production/myapp"
    );
    assert_eq!(bridge.bridge_id(), "tf-mesh");
}

#[test]
fn service_mesh_linkerd_rejects_garbage() {
    let bridge = ServiceMeshBridge::new(ServiceMeshBridgeConfig {
        bridge_id: "tf-mesh".into(),
        trust_domain: "example.com".into(),
    });
    assert!(bridge.accept_linkerd("garbage").is_err());
}
