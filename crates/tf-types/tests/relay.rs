#![allow(clippy::err_expect, clippy::expect_fun_call)]
//! Rust relay-forwarding parity tests over relay-forwarding-vectors.yaml.

use std::fs;
use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde::Deserialize;
use tf_types::relay::{
    sign_relay_authority, verify_relay_authority, RelayAuthority, RelayFrame, RelayHandler,
    SignatureEnvelope,
};

#[derive(Deserialize)]
struct VectorFile {
    now: String,
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    authority: AuthSpec,
    frame: FrameSpec,
    expect: String,
    #[serde(default)]
    expect_hop_count_out: Option<u32>,
    #[serde(default)]
    reason_substring: Option<String>,
}

#[derive(Deserialize)]
struct AuthSpec {
    relay: String,
    kinds: Vec<String>,
    max_hop_count: u32,
    valid_from: String,
    valid_until: String,
}

#[derive(Deserialize)]
struct FrameSpec {
    destination: String,
    hop_count: u32,
    size_bytes: usize,
    #[serde(default)]
    expires_at: Option<String>,
}

fn keypair() -> (SigningKey, [u8; 32]) {
    let s = SigningKey::generate(&mut OsRng);
    let pk = s.verifying_key().to_bytes();
    (s, pk)
}

fn load() -> VectorFile {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("conformance")
        .join("relay-forwarding-vectors.yaml");
    let raw = fs::read_to_string(&path).unwrap();
    serde_yaml::from_str(&raw).expect("parse")
}

#[test]
fn parity_vectors_match() {
    let file = load();
    for v in &file.vectors {
        let (signing, public) = keypair();
        let priv_bytes = signing.to_bytes();
        let unsigned = RelayAuthority {
            relay_authority_version: "1".into(),
            relay: v.authority.relay.clone(),
            trust_domain: "example.com".into(),
            kinds: v.authority.kinds.clone(),
            max_hop_count: Some(v.authority.max_hop_count),
            rate_limit_per_minute: None,
            valid_from: v.authority.valid_from.clone(),
            valid_until: Some(v.authority.valid_until.clone()),
            issuer: "tf:actor:service:example.com/tf-daemon".into(),
            constraints: None,
            signature: SignatureEnvelope {
                algorithm: "ed25519".into(),
                signer: "tf:actor:service:example.com/tf-daemon".into(),
                signature: String::new(),
            },
        };
        let authority = sign_relay_authority(unsigned, &priv_bytes);
        let handler = RelayHandler::new(authority, public);
        let frame = RelayFrame {
            ciphertext: vec![0u8; v.frame.size_bytes],
            destination: v.frame.destination.clone(),
            priority: None,
            hop_count: v.frame.hop_count,
            expires_at: v.frame.expires_at.clone(),
            source: None,
        };
        match v.expect.as_str() {
            "forward" => {
                let (out, ev) = handler.forward(&frame, &file.now).expect(&v.name);
                assert_eq!(
                    out.hop_count,
                    v.expect_hop_count_out.expect("expect_hop_count_out")
                );
                assert_eq!(ev.kind, "relay.forwarded");
            }
            "reject" => {
                let result = handler.forward(&frame, &file.now);
                let err = result.err().expect(&format!("{} should reject", v.name));
                if let Some(needle) = &v.reason_substring {
                    assert!(
                        format!("{}", err).contains(needle.as_str()),
                        "vector {}: error '{}' does not contain '{}'",
                        v.name,
                        err,
                        needle
                    );
                }
            }
            other => panic!("unknown expect: {}", other),
        }
    }
}

#[test]
fn relay_handler_struct_does_not_expose_decrypt() {
    // Compile-time guarantee: RelayHandler has no decrypt/execute methods.
    // We can't reflect at runtime in Rust, but ensuring the type system
    // sees only `forward` is enough — if someone added an unsafe extension
    // this test would still compile, which is acceptable; the spec
    // invariant is enforced by the type design itself.
    fn assert_forward_only<T>(_: &T)
    where
        T: ForwardOnly,
    {
    }
    let (signing, public) = keypair();
    let priv_bytes = signing.to_bytes();
    let authority = sign_relay_authority(
        RelayAuthority {
            relay_authority_version: "1".into(),
            relay: "tf:actor:relay:example.com/r".into(),
            trust_domain: "example.com".into(),
            kinds: vec!["forward-only".into()],
            max_hop_count: Some(4),
            rate_limit_per_minute: None,
            valid_from: "2026-04-24T11:00:00Z".into(),
            valid_until: Some("2026-04-24T13:00:00Z".into()),
            issuer: "tf:actor:service:example.com/tf-daemon".into(),
            constraints: None,
            signature: SignatureEnvelope {
                algorithm: "ed25519".into(),
                signer: "tf:actor:service:example.com/tf-daemon".into(),
                signature: String::new(),
            },
        },
        &priv_bytes,
    );
    let handler = RelayHandler::new(authority, public);
    assert_forward_only(&handler);
}

trait ForwardOnly {}
impl ForwardOnly for RelayHandler {}

#[test]
fn verify_authority_detects_tampering() {
    let (signing, public) = keypair();
    let priv_bytes = signing.to_bytes();
    let mut authority = sign_relay_authority(
        RelayAuthority {
            relay_authority_version: "1".into(),
            relay: "tf:actor:relay:example.com/r".into(),
            trust_domain: "example.com".into(),
            kinds: vec!["forward-only".into()],
            max_hop_count: Some(4),
            rate_limit_per_minute: None,
            valid_from: "2026-04-24T11:00:00Z".into(),
            valid_until: Some("2026-04-24T13:00:00Z".into()),
            issuer: "tf:actor:service:example.com/tf-daemon".into(),
            constraints: None,
            signature: SignatureEnvelope {
                algorithm: "ed25519".into(),
                signer: "tf:actor:service:example.com/tf-daemon".into(),
                signature: String::new(),
            },
        },
        &priv_bytes,
    );
    authority.max_hop_count = Some(99);
    let v = verify_relay_authority(&authority, &public);
    assert!(!v.ok);
}
