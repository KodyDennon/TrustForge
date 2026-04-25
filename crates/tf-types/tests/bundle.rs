//! Rust .tfbundle seal/open + transparency anchor + RFC 3161 tests.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand::RngCore;
use serde_json::json;
use tf_types::bundle::{
    build_rfc3161_request, encrypted_signing_bytes, open_bundle, seal_bundle,
    BundleRecipient, MemoryAnchor,
};
use x25519_dalek::{PublicKey, StaticSecret};

fn keypair() -> (SigningKey, [u8; 32]) {
    let s = SigningKey::generate(&mut OsRng);
    let pk = s.verifying_key().to_bytes();
    (s, pk)
}

fn x25519_keypair() -> ([u8; 32], [u8; 32]) {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let secret = StaticSecret::from(seed);
    let pub_bytes = PublicKey::from(&secret).to_bytes();
    (seed, pub_bytes)
}

fn sample_bundle() -> serde_json::Value {
    json!({
        "bundle_version": "1",
        "events": [
            {
                "event_version": "1",
                "id": "ev-1",
                "type": "rpc.call",
                "actor_id": "tf:actor:agent:example.com/code-helper",
                "timestamp": "2026-04-24T12:00:00Z",
                "level": "L1",
                "signature": { "algorithm": "ed25519", "signer": "tf:actor:agent:example.com/x", "signature": "AAAA" }
            }
        ],
        "signature": { "algorithm": "ed25519", "signer": "tf:actor:service:example.com/d", "signature": "AAAA" }
    })
}

#[test]
fn seal_and_open_round_trip() {
    let (recipient_priv, recipient_pub) = x25519_keypair();
    let (signer, signer_pub) = keypair();
    let priv_bytes = signer.to_bytes();
    let enc = seal_bundle(
        &sample_bundle(),
        &[BundleRecipient {
            actor: "tf:actor:human:example.com/alice".into(),
            kem_public: recipient_pub,
            key_id: Some("alice-kem-1".into()),
        }],
        "L4",
        &priv_bytes,
        "tf:actor:service:example.com/tf-daemon",
    );
    assert_eq!(enc.level, "L4");
    assert_eq!(enc.wrapped_keys.len(), 1);
    let opened = open_bundle(
        &enc,
        &recipient_priv,
        "tf:actor:human:example.com/alice",
        Some(&signer_pub),
    )
    .expect("open");
    assert_eq!(opened["events"][0]["id"], "ev-1");
}

#[test]
fn non_recipient_cannot_open() {
    let (_recipient_priv, recipient_pub) = x25519_keypair();
    let (other_priv, _) = x25519_keypair();
    let (signer, _) = keypair();
    let priv_bytes = signer.to_bytes();
    let enc = seal_bundle(
        &sample_bundle(),
        &[BundleRecipient {
            actor: "tf:actor:human:example.com/alice".into(),
            kem_public: recipient_pub,
            key_id: None,
        }],
        "L4",
        &priv_bytes,
        "tf:actor:service:example.com/tf-daemon",
    );
    let result = open_bundle(&enc, &other_priv, "tf:actor:human:example.com/alice", None);
    assert!(result.is_err());
}

#[test]
fn open_validates_outer_signature_when_pubkey_provided() {
    let (recipient_priv, recipient_pub) = x25519_keypair();
    let (signer, _) = keypair();
    let (_other_signer, other_signer_pub) = keypair();
    let priv_bytes = signer.to_bytes();
    let enc = seal_bundle(
        &sample_bundle(),
        &[BundleRecipient {
            actor: "tf:actor:human:example.com/alice".into(),
            kem_public: recipient_pub,
            key_id: None,
        }],
        "L4",
        &priv_bytes,
        "tf:actor:service:example.com/tf-daemon",
    );
    let result = open_bundle(
        &enc,
        &recipient_priv,
        "tf:actor:human:example.com/alice",
        Some(&other_signer_pub),
    );
    assert!(result.is_err());
}

#[test]
fn memory_anchor_round_trip() {
    let anchor = MemoryAnchor::new();
    let bytes = b"hello world";
    let proof = anchor.submit(bytes);
    assert_eq!(proof["kind"], "memory");
    assert!(anchor.verify_inclusion(bytes, &proof));
    assert!(!anchor.verify_inclusion(b"different", &proof));
}

#[test]
fn rfc3161_request_starts_with_sequence_and_contains_sha256_oid() {
    let req = build_rfc3161_request(b"payload");
    assert_eq!(req[0], 0x30);
    let needle = [
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    ];
    let mut found = false;
    for window in req.windows(needle.len()) {
        if window == needle {
            found = true;
            break;
        }
    }
    assert!(found, "SHA-256 OID not found in TimeStampReq");
}

#[test]
fn encrypted_signing_bytes_is_stable() {
    let (recipient_priv, recipient_pub) = x25519_keypair();
    let _ = recipient_priv;
    let (signer, _) = keypair();
    let priv_bytes = signer.to_bytes();
    let enc = seal_bundle(
        &sample_bundle(),
        &[BundleRecipient {
            actor: "tf:actor:human:example.com/alice".into(),
            kem_public: recipient_pub,
            key_id: None,
        }],
        "L4",
        &priv_bytes,
        "tf:actor:service:example.com/tf-daemon",
    );
    let a = encrypted_signing_bytes(&enc);
    let b = encrypted_signing_bytes(&enc.clone());
    assert_eq!(a, b);
}
