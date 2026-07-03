//! Rust federation tests.

use tf_types::encoding::STANDARD;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use tf_types::federation::{
    attestation_signing_bytes, sign_federation_attestation, verify_federation_attestation,
    FederatedTrustStore, SignAttestationArgs, TrustBundleEntry,
};

fn keypair() -> (SigningKey, [u8; 32]) {
    let s = SigningKey::generate(&mut OsRng);
    let pk = s.verifying_key().to_bytes();
    (s, pk)
}

#[test]
fn signed_attestation_round_trips() {
    let (signing, public) = keypair();
    let priv_bytes = signing.to_bytes();
    let att = sign_federation_attestation(SignAttestationArgs {
        attestation_id: "fed-1".into(),
        issuer_domain: "example.com".into(),
        subject_domain: "partner.example.org".into(),
        subject_actor: Some("tf:actor:agent:partner.example.org/code-helper".into()),
        scope: Some(vec!["file.read".into(), "file.write".into()]),
        trust_levels_granted: Some(vec!["T3".into()]),
        trust_bundle: vec![TrustBundleEntry {
            kind: "ed25519".into(),
            value: STANDARD.encode([1u8; 32]),
            key_id: Some("partner-root".into()),
        }],
        constraints: None,
        issued_at: Some("2026-04-24T11:00:00Z".into()),
        valid_until: "2026-12-31T23:59:59Z".into(),
        issuer: "tf:actor:service:example.com/tf-daemon".into(),
        private_key: priv_bytes,
    })
    .expect("sign");
    let v = verify_federation_attestation(&att, &public, Some("2026-04-24T12:00:00Z"));
    assert!(v.ok, "expected ok, got {:?}", v.reason);
}

#[test]
fn verify_rejects_tampered_scope() {
    let (signing, public) = keypair();
    let priv_bytes = signing.to_bytes();
    let mut att = sign_federation_attestation(SignAttestationArgs {
        attestation_id: "fed-x".into(),
        issuer_domain: "example.com".into(),
        subject_domain: "partner.example.org".into(),
        subject_actor: None,
        scope: None,
        trust_levels_granted: None,
        trust_bundle: vec![TrustBundleEntry {
            kind: "ed25519".into(),
            value: STANDARD.encode([0u8; 32]),
            key_id: None,
        }],
        constraints: None,
        issued_at: Some("2026-04-24T11:00:00Z".into()),
        valid_until: "2026-12-31T23:59:59Z".into(),
        issuer: "tf:actor:service:example.com/tf-daemon".into(),
        private_key: priv_bytes,
    })
    .unwrap();
    att.scope = Some(vec!["payment.charge".into()]);
    let v = verify_federation_attestation(&att, &public, Some("2026-04-24T12:00:00Z"));
    assert!(!v.ok);
}

#[test]
fn verify_rejects_expired_attestation() {
    let (signing, public) = keypair();
    let priv_bytes = signing.to_bytes();
    let att = sign_federation_attestation(SignAttestationArgs {
        attestation_id: "fed-exp".into(),
        issuer_domain: "example.com".into(),
        subject_domain: "partner.example.org".into(),
        subject_actor: None,
        scope: None,
        trust_levels_granted: None,
        trust_bundle: vec![TrustBundleEntry {
            kind: "ed25519".into(),
            value: STANDARD.encode([0u8; 32]),
            key_id: None,
        }],
        constraints: None,
        issued_at: Some("2024-01-01T00:00:00Z".into()),
        valid_until: "2024-12-31T23:59:59Z".into(),
        issuer: "tf:actor:service:example.com/tf-daemon".into(),
        private_key: priv_bytes,
    })
    .unwrap();
    let v = verify_federation_attestation(&att, &public, Some("2026-04-24T12:00:00Z"));
    assert!(!v.ok);
    assert!(v.reason.unwrap_or_default().contains("window"));
}

#[test]
fn signing_bytes_is_stable() {
    let (signing, _public) = keypair();
    let priv_bytes = signing.to_bytes();
    let att = sign_federation_attestation(SignAttestationArgs {
        attestation_id: "fed-stable".into(),
        issuer_domain: "example.com".into(),
        subject_domain: "partner.example.org".into(),
        subject_actor: None,
        scope: None,
        trust_levels_granted: None,
        trust_bundle: vec![TrustBundleEntry {
            kind: "ed25519".into(),
            value: STANDARD.encode([0u8; 32]),
            key_id: None,
        }],
        constraints: None,
        issued_at: Some("2026-04-24T11:00:00Z".into()),
        valid_until: "2030-01-01T00:00:00Z".into(),
        issuer: "tf:actor:service:example.com/tf-daemon".into(),
        private_key: priv_bytes,
    })
    .unwrap();
    let a = attestation_signing_bytes(&att);
    let b = attestation_signing_bytes(&att.clone());
    assert_eq!(a, b);
}

#[test]
fn store_verify_foreign_succeeds_with_matching_bundle_key() {
    let (signing, _) = keypair();
    let priv_bytes = signing.to_bytes();
    let partner = SigningKey::generate(&mut OsRng);
    let partner_pub = partner.verifying_key().to_bytes();
    let att = sign_federation_attestation(SignAttestationArgs {
        attestation_id: "fed-1".into(),
        issuer_domain: "example.com".into(),
        subject_domain: "partner.example.org".into(),
        subject_actor: Some("tf:actor:agent:partner.example.org/code-helper".into()),
        scope: Some(vec!["file.read".into()]),
        trust_levels_granted: Some(vec!["T3".into()]),
        trust_bundle: vec![TrustBundleEntry {
            kind: "ed25519".into(),
            value: STANDARD.encode(partner_pub),
            key_id: Some("partner-root".into()),
        }],
        constraints: None,
        issued_at: Some("2026-04-24T11:00:00Z".into()),
        valid_until: "2030-12-31T23:59:59Z".into(),
        issuer: "tf:actor:service:example.com/tf-daemon".into(),
        private_key: priv_bytes,
    })
    .unwrap();
    let mut store = FederatedTrustStore::new();
    store.add(att);

    let message = b"partner-signed payload";
    let sig = partner.sign(message);
    let result = store.verify_foreign(
        "tf:actor:agent:partner.example.org/code-helper",
        "partner.example.org",
        Some((message, sig.to_bytes().as_ref())),
        Some("2026-04-24T12:00:00Z"),
    );
    assert!(result.ok, "expected ok, got {:?}", result.reason);
    assert_eq!(result.matched_attestation_id.as_deref(), Some("fed-1"));
    assert_eq!(
        result.trust_levels.as_deref(),
        Some(["T3".to_string()].as_slice())
    );
}

#[test]
fn store_verify_foreign_rejects_unknown_signer() {
    let (signing, _) = keypair();
    let priv_bytes = signing.to_bytes();
    let partner = SigningKey::generate(&mut OsRng);
    let partner_pub = partner.verifying_key().to_bytes();
    let att = sign_federation_attestation(SignAttestationArgs {
        attestation_id: "fed-2".into(),
        issuer_domain: "example.com".into(),
        subject_domain: "partner.example.org".into(),
        subject_actor: None,
        scope: None,
        trust_levels_granted: None,
        trust_bundle: vec![TrustBundleEntry {
            kind: "ed25519".into(),
            value: STANDARD.encode(partner_pub),
            key_id: None,
        }],
        constraints: None,
        issued_at: Some("2026-04-24T11:00:00Z".into()),
        valid_until: "2030-12-31T23:59:59Z".into(),
        issuer: "tf:actor:service:example.com/tf-daemon".into(),
        private_key: priv_bytes,
    })
    .unwrap();
    let mut store = FederatedTrustStore::new();
    store.add(att);
    let stranger = SigningKey::generate(&mut OsRng);
    let message = b"intruder";
    let sig = stranger.sign(message);
    let result = store.verify_foreign(
        "tf:actor:agent:partner.example.org/code-helper",
        "partner.example.org",
        Some((message, sig.to_bytes().as_ref())),
        Some("2026-04-24T12:00:00Z"),
    );
    assert!(!result.ok);
}
