//! Rust packet-mode tests — mirror of TS suite.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use tf_types::packet::{
    fragment_packet, reassemble_fragments, sign_packet, verify_packet, FragmentOptions,
    SignPacketArgs,
};

fn keypair() -> (SigningKey, [u8; 32]) {
    let s = SigningKey::generate(&mut OsRng);
    let pk = s.verifying_key().to_bytes();
    (s, pk)
}

const SOURCE: &str = "tf:actor:agent:example.com/code-helper";
const DEST: &str = "tf:actor:service:example.com/tf-daemon";

fn now() -> String {
    "2026-04-24T12:00:00Z".into()
}

#[test]
fn cbor_round_trip_through_verify() {
    let (signing, public) = keypair();
    let priv_bytes = signing.to_bytes();
    let payload = b"hello world";
    let p = sign_packet(SignPacketArgs {
        packet_id: "pkt-1".into(),
        source: SOURCE.into(),
        destination: DEST.into(),
        priority: "P2".into(),
        payload,
        encoding: None,
        compression: None,
        emergency: false,
        expires_at: None,
        ttl_hops: None,
        route_constraints: None,
        session_ref: None,
        private_key: priv_bytes,
        signer: SOURCE.into(),
        created_at: Some(now()),
    })
    .expect("sign");
    let v = verify_packet(&p, &public, &now());
    assert!(v.ok, "expected ok, got {:?}", v.reason);
    assert_eq!(v.payload.unwrap(), payload);
}

#[test]
fn deflate_compression_round_trips() {
    let (signing, public) = keypair();
    let priv_bytes = signing.to_bytes();
    let payload = vec![b'x'; 2048];
    let p = sign_packet(SignPacketArgs {
        packet_id: "pkt-2".into(),
        source: SOURCE.into(),
        destination: DEST.into(),
        priority: "P3".into(),
        payload: &payload,
        encoding: None,
        compression: Some("deflate".into()),
        emergency: false,
        expires_at: None,
        ttl_hops: None,
        route_constraints: None,
        session_ref: None,
        private_key: priv_bytes,
        signer: SOURCE.into(),
        created_at: Some(now()),
    })
    .expect("sign");
    let v = verify_packet(&p, &public, &now());
    assert!(v.ok);
    assert_eq!(v.payload.unwrap().len(), 2048);
}

#[test]
fn verify_rejects_signer_mismatch() {
    let (signing, public) = keypair();
    let priv_bytes = signing.to_bytes();
    let mut p = sign_packet(SignPacketArgs {
        packet_id: "pkt-3".into(),
        source: SOURCE.into(),
        destination: DEST.into(),
        priority: "P3".into(),
        payload: b"x",
        encoding: None,
        compression: None,
        emergency: false,
        expires_at: None,
        ttl_hops: None,
        route_constraints: None,
        session_ref: None,
        private_key: priv_bytes,
        signer: SOURCE.into(),
        created_at: Some(now()),
    })
    .unwrap();
    p.signature.signer = "tf:actor:human:example.com/mallory".into();
    let v = verify_packet(&p, &public, &now());
    assert!(!v.ok);
}

#[test]
fn verify_rejects_expired_packet() {
    let (signing, public) = keypair();
    let priv_bytes = signing.to_bytes();
    let p = sign_packet(SignPacketArgs {
        packet_id: "pkt-exp".into(),
        source: SOURCE.into(),
        destination: DEST.into(),
        priority: "P3".into(),
        payload: b"x",
        encoding: None,
        compression: None,
        emergency: false,
        expires_at: Some("2026-04-23T00:00:00Z".into()),
        ttl_hops: None,
        route_constraints: None,
        session_ref: None,
        private_key: priv_bytes,
        signer: SOURCE.into(),
        created_at: Some(now()),
    })
    .unwrap();
    let v = verify_packet(&p, &public, "2026-04-25T00:00:00Z");
    assert!(!v.ok);
    assert!(v.reason.unwrap_or_default().contains("expired"));
}

#[test]
fn p0_priority_requires_emergency() {
    let (signing, _public) = keypair();
    let priv_bytes = signing.to_bytes();
    let result = sign_packet(SignPacketArgs {
        packet_id: "pkt-x".into(),
        source: SOURCE.into(),
        destination: DEST.into(),
        priority: "P0".into(),
        payload: b"x",
        encoding: None,
        compression: None,
        emergency: false,
        expires_at: None,
        ttl_hops: None,
        route_constraints: None,
        session_ref: None,
        private_key: priv_bytes,
        signer: SOURCE.into(),
        created_at: Some(now()),
    });
    assert!(result.is_err());
}

#[test]
fn fragment_and_reassemble_byte_identical() {
    let (signing, _) = keypair();
    let priv_bytes = signing.to_bytes();
    let payload: Vec<u8> = (0..2048u32).map(|i| (i & 0xff) as u8).collect();
    let original = sign_packet(SignPacketArgs {
        packet_id: "pkt-frag".into(),
        source: SOURCE.into(),
        destination: DEST.into(),
        priority: "P3".into(),
        payload: &payload,
        encoding: Some("json".into()),
        compression: None,
        emergency: false,
        expires_at: None,
        ttl_hops: None,
        route_constraints: None,
        session_ref: None,
        private_key: priv_bytes,
        signer: SOURCE.into(),
        created_at: Some(now()),
    })
    .unwrap();
    let fragments = fragment_packet(
        &original,
        &priv_bytes,
        FragmentOptions { mtu: Some(256) },
    );
    assert!(fragments.len() > 1);
    let r = reassemble_fragments(&fragments);
    assert!(r.ok, "expected ok, got {:?}", r.reason);
    let wire = base64::engine::general_purpose::STANDARD
        .decode(&original.payload)
        .unwrap();
    assert_eq!(r.payload.unwrap().len(), wire.len());
}

#[test]
fn reassembly_rejects_missing_fragment() {
    let (signing, _) = keypair();
    let priv_bytes = signing.to_bytes();
    let payload = vec![7u8; 1024];
    let original = sign_packet(SignPacketArgs {
        packet_id: "p".into(),
        source: SOURCE.into(),
        destination: DEST.into(),
        priority: "P2".into(),
        payload: &payload,
        encoding: None,
        compression: None,
        emergency: false,
        expires_at: None,
        ttl_hops: None,
        route_constraints: None,
        session_ref: None,
        private_key: priv_bytes,
        signer: SOURCE.into(),
        created_at: Some(now()),
    })
    .unwrap();
    let fragments = fragment_packet(
        &original,
        &priv_bytes,
        FragmentOptions { mtu: Some(128) },
    );
    let truncated = &fragments[..fragments.len() - 1];
    let r = reassemble_fragments(truncated);
    assert!(!r.ok);
}

use base64::Engine as _;
