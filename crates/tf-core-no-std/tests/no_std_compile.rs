//! Smoke test that exercises every module of `tf-core-no-std` from a
//! single integration test target. The crate itself is `#![no_std]`;
//! this test executes on the host (which provides `std`) but only
//! calls into the crate's no_std API surface, so a regression that
//! sneaks in `std::*` somewhere will surface here on top of the
//! dedicated `cargo build --target thumbv7em-none-eabihf` step in CI.

#![cfg_attr(not(test), no_std)]

use ed25519_compact::{KeyPair, Seed};
use sha2::{Digest, Sha256};
use tf_core_no_std::nonce_cache::{ReceiverDecision, RejectReason};
use tf_core_no_std::orl::{OfflineRevocationListChecker, OrlError, RevokedKind};
use tf_core_no_std::packet::{sign_packet, verify_packet, VerifyError};
use tf_core_no_std::relay::{
    relay_authority_signing_bytes, verify_relay_authority, RelayAuthority, SignatureEnvelope,
};

#[test]
fn packet_round_trip() {
    let seed = Seed::from_slice(&[5u8; 32]).unwrap();
    let kp = KeyPair::from_seed(seed);
    let pk: [u8; 32] = kp.pk.as_ref().try_into().unwrap();
    let signer = "tf:actor:agent:example.com/sensor";
    let pkt = sign_packet(
        b"telemetry-frame",
        &seed,
        signer,
        "pkt-9001",
        signer,
        "tf:actor:service:example.com/ingest",
        "P3",
        Some("2099-01-01T00:00:00Z"),
    )
    .expect("sign ok");
    verify_packet(&pkt, &pk, "2026-04-25T00:00:00Z").expect("verify ok");
}

#[test]
fn relay_authority_round_trip() {
    use heapless::String as HString;
    use heapless::Vec as HVec;

    let seed = Seed::from_slice(&[6u8; 32]).unwrap();
    let kp = KeyPair::from_seed(seed);
    let pk: [u8; 32] = kp.pk.as_ref().try_into().unwrap();

    fn hs<const N: usize>(s: &str) -> HString<N> {
        let mut h = HString::new();
        h.push_str(s).unwrap();
        h
    }
    let mut kinds: HVec<HString<32>, 16> = HVec::new();
    kinds.push(hs::<32>("packet")).unwrap();
    let mut auth = RelayAuthority {
        relay_authority_version: hs("1"),
        relay: hs("tf:actor:relay:example.com/r1"),
        trust_domain: hs("example.com"),
        kinds,
        max_hop_count: Some(3),
        rate_limit_per_minute: None,
        valid_from: hs("2026-01-01T00:00:00Z"),
        valid_until: None,
        issuer: hs("tf:actor:authority:example.com/root"),
        signature: SignatureEnvelope {
            algorithm: hs("ed25519"),
            signer: hs("tf:actor:authority:example.com/root"),
            signature: HVec::new(),
        },
    };
    let digest = relay_authority_signing_bytes(&auth);
    let sig = kp.sk.sign(digest, None);
    auth.signature
        .signature
        .extend_from_slice(sig.as_ref())
        .unwrap();
    assert!(verify_relay_authority(&auth, &pk));
}

#[test]
fn orl_load_and_lookup() {
    let seed = Seed::from_slice(&[8u8; 32]).unwrap();
    let kp = KeyPair::from_seed(seed);
    let pk: [u8; 32] = kp.pk.as_ref().try_into().unwrap();

    let mut buf: heapless::Vec<u8, 4096> = heapless::Vec::new();
    buf.push(1u8).unwrap(); // version
    let issuer = b"tf:actor:authority:example.com/root";
    let issued = b"2026-01-01T00:00:00Z";
    let valid_until = b"2099-01-01T00:00:00Z";
    write_lp(&mut buf, issuer);
    write_lp(&mut buf, issued);
    write_lp(&mut buf, valid_until);
    let count: u32 = 1;
    buf.extend_from_slice(&count.to_be_bytes()).unwrap();
    buf.push(RevokedKind::Key.to_u8()).unwrap();
    let key_id = b"tf:key:abc";
    write_lp(&mut buf, key_id);

    let mut h = Sha256::new();
    h.update(&buf);
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&h.finalize());
    let sig = kp.sk.sign(digest, None);
    buf.extend_from_slice(sig.as_ref()).unwrap();

    let orl = OfflineRevocationListChecker::new(&buf, &pk, "2026-04-25T00:00:00Z").expect("load");
    assert!(orl.is_revoked(RevokedKind::Key, "tf:key:abc"));
    assert!(!orl.is_revoked(RevokedKind::Actor, "tf:key:abc"));
}

#[test]
fn nonce_cache_replay_rejection() {
    #[cfg(feature = "alloc")]
    {
        use tf_core_no_std::nonce_cache::PacketReceiver;
        let mut rx = PacketReceiver::new(4);
        let now = "2026-04-25T00:00:00Z";
        assert_eq!(rx.observe("p1", None, now), ReceiverDecision::Accept);
        assert_eq!(
            rx.observe("p1", None, now),
            ReceiverDecision::Reject(RejectReason::Replay)
        );
    }
    #[cfg(not(feature = "alloc"))]
    {
        use tf_core_no_std::nonce_cache::PacketReceiver;
        let mut rx: PacketReceiver<4> = PacketReceiver::new();
        let now = "2026-04-25T00:00:00Z";
        assert_eq!(rx.observe("p1", None, now), ReceiverDecision::Accept);
        assert_eq!(
            rx.observe("p1", None, now),
            ReceiverDecision::Reject(RejectReason::Replay)
        );
    }
}

#[test]
fn verify_rejects_tamper_e2e() {
    let seed = Seed::from_slice(&[15u8; 32]).unwrap();
    let kp = KeyPair::from_seed(seed);
    let pk: [u8; 32] = kp.pk.as_ref().try_into().unwrap();
    let signer = "tf:actor:agent:example.com/x";
    let mut pkt = sign_packet(
        b"abc",
        &seed,
        signer,
        "pkt-1",
        signer,
        "tf:actor:service:example.com/y",
        "P2",
        None,
    )
    .unwrap();
    pkt.payload[0] ^= 0xff;
    let r = verify_packet(&pkt, &pk, "2026-04-25T00:00:00Z");
    assert_eq!(r, Err(VerifyError::SignatureInvalid));
}

#[test]
fn orl_truncated_buffer_errs() {
    let r = OfflineRevocationListChecker::new(&[1u8, 0, 0, 0], &[0u8; 32], "2026-04-25T00:00:00Z");
    assert_eq!(r.err(), Some(OrlError::Truncated));
}

fn write_lp(buf: &mut heapless::Vec<u8, 4096>, data: &[u8]) {
    let len = data.len() as u32;
    buf.extend_from_slice(&len.to_be_bytes()).unwrap();
    buf.extend_from_slice(data).unwrap();
}
