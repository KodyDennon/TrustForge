//! Rust session-migration tests — mirror of TS suite.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use tf_types::session_migration::{
    migrate_session, verify_session_migration, Ratchet, TransportBinding,
};

fn keypair() -> (SigningKey, [u8; 32]) {
    let s = SigningKey::generate(&mut OsRng);
    let pk = s.verifying_key().to_bytes();
    (s, pk)
}

fn from_binding() -> TransportBinding {
    TransportBinding {
        binding_version: "1".into(),
        kind: "websocket".into(),
        endpoint: Some("wss://daemon.example.com/tf".into()),
        exporter_key: None,
        peer_cert_fingerprint: None,
        tls_alpn: None,
        established_at: Some("2026-04-24T12:00:00Z".into()),
        metadata: None,
    }
}

fn to_binding() -> TransportBinding {
    TransportBinding {
        binding_version: "1".into(),
        kind: "quic".into(),
        endpoint: Some("quic://daemon.example.com:7443".into()),
        exporter_key: None,
        peer_cert_fingerprint: None,
        tls_alpn: None,
        established_at: Some("2026-04-24T12:05:00Z".into()),
        metadata: None,
    }
}

#[test]
fn round_trip_signed_migration_verifies() {
    let (signing, public) = keypair();
    let priv_bytes = signing.to_bytes();
    let m = migrate_session(
        "AAECAwQFBgcICQoLDA0ODw==",
        1,
        from_binding(),
        to_binding(),
        true,
        Some("client roamed; upgrade to QUIC"),
        "tf:actor:agent:example.com/code-helper",
        &priv_bytes,
        None,
    );
    assert_eq!(m.generation, 1);
    assert_eq!(m.rotated_keys, Some(true));
    let v = verify_session_migration(&m, &public, None, Some("AAECAwQFBgcICQoLDA0ODw=="));
    assert!(v.ok, "expected ok, got {:?}", v.reason);
}

#[test]
fn verify_rejects_tampered_to_binding() {
    let (signing, public) = keypair();
    let priv_bytes = signing.to_bytes();
    let mut m = migrate_session(
        "AAECAwQFBgcICQoLDA0ODw==",
        1,
        from_binding(),
        to_binding(),
        false,
        None,
        "tf:actor:agent:example.com/x",
        &priv_bytes,
        None,
    );
    m.to_binding.endpoint = Some("quic://attacker.example.com".into());
    let v = verify_session_migration(&m, &public, None, None);
    assert!(!v.ok);
}

#[test]
fn verify_rejects_replay() {
    let (signing, public) = keypair();
    let priv_bytes = signing.to_bytes();
    let m = migrate_session(
        "AAECAwQFBgcICQoLDA0ODw==",
        1,
        from_binding(),
        to_binding(),
        false,
        None,
        "tf:actor:agent:example.com/x",
        &priv_bytes,
        None,
    );
    let v = verify_session_migration(&m, &public, Some(1), None);
    assert!(!v.ok);
    assert!(v.reason.unwrap_or_default().contains("replay"));
}

#[test]
fn ratchet_rotates_after_max_messages() {
    let mut r = Ratchet::new([1u8; 32], Some(3));
    assert_eq!(r.generation(), 0);
    assert!(!r.observe_message());
    assert!(!r.observe_message());
    assert!(r.observe_message());
    assert_eq!(r.generation(), 1);
}

#[test]
fn two_ratchets_with_same_seed_produce_same_sequence() {
    let mut a = Ratchet::new([7u8; 32], None);
    let mut b = Ratchet::new([7u8; 32], None);
    a.rotate();
    b.rotate();
    assert_eq!(a.key(), b.key());
}
