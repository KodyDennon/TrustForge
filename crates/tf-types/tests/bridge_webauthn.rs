//! Rust WebAuthn bridge tests + parity over conformance/bridge-vectors.yaml.

use std::fs;
use std::path::PathBuf;

use serde::Deserialize;

use tf_types::bridge_webauthn::{WebAuthnBridge, WebAuthnBridgeConfig, WebAuthnCredential};
use tf_types::bridges::{Bridge, BridgeError, BridgeKind};
use tf_types::generated::{ActorType, AuthorityRoot_Kind, TrustLevel};

#[derive(Deserialize)]
struct VectorsFile {
    webauthn: Vec<WebAuthnVector>,
}

#[derive(Deserialize)]
struct WebAuthnVector {
    name: String,
    credential: WebAuthnCredential,
    actor_id: String,
    trust_levels: Vec<String>,
    authority_root_kind: String,
    authority_root_id: String,
}

fn load() -> VectorsFile {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("conformance")
        .join("bridge-vectors.yaml");
    let raw = fs::read_to_string(&path).unwrap();
    serde_yaml::from_str(&raw).expect("parse bridge-vectors.yaml")
}

fn make_bridge(rp_id: &str) -> WebAuthnBridge {
    WebAuthnBridge::new(WebAuthnBridgeConfig {
        bridge_id: "tf-webauthn".into(),
        trust_domain: "example.com".into(),
        rp_id: rp_id.into(),
        allowed_algorithms: None,
    })
}

#[test]
fn parity_vectors_promote_credentials_to_identities() {
    for v in load().webauthn {
        let bridge = make_bridge(&v.credential.rp_id);
        let identity = bridge.accept(&v.credential).expect(&v.name);
        assert_eq!(identity.actor_id, v.actor_id, "vector {} actor_id", v.name);
        assert_eq!(identity.actor_type, ActorType::Human);
        let levels: Vec<String> = identity
            .trust_levels
            .iter()
            .map(|t| match t {
                TrustLevel::T0 => "T0",
                TrustLevel::T1 => "T1",
                TrustLevel::T2 => "T2",
                TrustLevel::T3 => "T3",
                TrustLevel::T4 => "T4",
                TrustLevel::T5 => "T5",
                TrustLevel::T6 => "T6",
                TrustLevel::T7 => "T7",
            })
            .map(String::from)
            .collect();
        assert_eq!(levels, v.trust_levels, "vector {} trust_levels", v.name);
        assert_eq!(identity.authority_roots.len(), 1);
        let root = &identity.authority_roots[0];
        let root_kind_str = match root.kind {
            AuthorityRoot_Kind::Owner => "owner",
            AuthorityRoot_Kind::Organization => "organization",
            AuthorityRoot_Kind::Manufacturer => "manufacturer",
            AuthorityRoot_Kind::HardwareKey => "hardware-key",
            AuthorityRoot_Kind::Federation => "federation",
            AuthorityRoot_Kind::ComplianceIssuer => "compliance-issuer",
            AuthorityRoot_Kind::LocalEmergency => "local-emergency",
            AuthorityRoot_Kind::TransparencyAnchor => "transparency-anchor",
            AuthorityRoot_Kind::TrustDomain => "trust-domain",
        };
        assert_eq!(
            root_kind_str, v.authority_root_kind,
            "vector {} root kind",
            v.name
        );
        assert_eq!(root.id, v.authority_root_id, "vector {} root id", v.name);
    }
}

#[test]
fn rejects_mismatched_rp_id() {
    let bridge = make_bridge("trustforge.test");
    let cred = WebAuthnCredential {
        credential_id: "cid".into(),
        public_key: "AA==".into(),
        algorithm: "ed25519".into(),
        rp_id: "evil.example".into(),
        user_handle: "u1".into(),
        aaguid: None,
        attestation_format: None,
        valid_from: None,
        valid_until: None,
    };
    assert!(matches!(
        bridge.accept(&cred),
        Err(BridgeError::Rejected(_))
    ));
}

#[test]
fn rejects_disallowed_algorithm() {
    let bridge = WebAuthnBridge::new(WebAuthnBridgeConfig {
        bridge_id: "tf-wa".into(),
        trust_domain: "example.com".into(),
        rp_id: "example.com".into(),
        allowed_algorithms: Some(vec!["p256".into()]),
    });
    let cred = WebAuthnCredential {
        credential_id: "cid".into(),
        public_key: "AA==".into(),
        algorithm: "ed25519".into(),
        rp_id: "example.com".into(),
        user_handle: "u".into(),
        aaguid: None,
        attestation_format: None,
        valid_from: None,
        valid_until: None,
    };
    assert!(matches!(
        bridge.accept(&cred),
        Err(BridgeError::Rejected(_))
    ));
}

#[test]
fn round_trip_credential_back_to_credential() {
    let bridge = make_bridge("example.com");
    let original = WebAuthnCredential {
        credential_id: "cid-42".into(),
        public_key: "MCowBQYDK2VwAyEA8wHnF5mJ+0c5KqyGxWXcJ+7p3qGzlHcQmL5ZhqQvJ1o=".into(),
        algorithm: "ed25519".into(),
        rp_id: "example.com".into(),
        user_handle: "user-42".into(),
        aaguid: Some("aaaa-bbbb".into()),
        attestation_format: None,
        valid_from: None,
        valid_until: None,
    };
    let identity = bridge.accept(&original).unwrap();
    let back = bridge.project(&identity).unwrap();
    assert_eq!(back.credential_id, original.credential_id);
    assert_eq!(back.public_key, original.public_key);
    assert_eq!(back.algorithm, original.algorithm);
    assert_eq!(back.rp_id, original.rp_id);
    assert_eq!(back.user_handle, original.user_handle);
    assert_eq!(back.aaguid, original.aaguid);
}

#[test]
fn project_rejects_non_human_actor() {
    use tf_types::generated::{
        ActorIdentity, ActorIdentity_IdentityVersion, AuthorityRoot, PublicKey, PublicKey_Purpose,
        TrustLevel,
    };
    let bridge = make_bridge("example.com");
    let mut identity = bridge
        .accept(&WebAuthnCredential {
            credential_id: "cid".into(),
            public_key: "AA==".into(),
            algorithm: "ed25519".into(),
            rp_id: "example.com".into(),
            user_handle: "u".into(),
            aaguid: None,
            attestation_format: None,
            valid_from: None,
            valid_until: None,
        })
        .unwrap();
    identity.actor_type = ActorType::Agent;
    let result = bridge.project(&identity);
    assert!(matches!(result, Err(BridgeError::Unsupported(_))));
    let _ = (
        ActorIdentity_IdentityVersion::V1,
        AuthorityRoot {
            kind: AuthorityRoot_Kind::HardwareKey,
            id: "x".into(),
        },
        PublicKey {
            key_id: "x".into(),
            algorithm: "ed25519".into(),
            public_key: "AA==".into(),
            purpose: PublicKey_Purpose::Signing,
            valid_from: None,
            valid_until: None,
        },
        TrustLevel::T4,
    ); // suppress unused-import warnings
}

#[test]
fn bridge_kind_is_webauthn() {
    let bridge = make_bridge("example.com");
    assert!(matches!(bridge.kind(), BridgeKind::Webauthn));
    assert_eq!(bridge.bridge_id(), "tf-webauthn");
}
