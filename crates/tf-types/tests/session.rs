//! Rust session tests mirroring `tools/tf-types-ts/tests/session.test.ts`.

use rand::rngs::OsRng;
use serde_json::json;

use tf_types::crypto::Ed25519Signer;
use tf_types::session::{
    Auth, HelloI, HelloR, Initiator, Responder, SessionConfig, SessionError, SessionFrame,
    SessionState,
};

struct Pair {
    initiator: Initiator,
    responder: Responder,
}

fn make_pair() -> Pair {
    let i_id = Ed25519Signer::generate(&mut OsRng);
    let r_id = Ed25519Signer::generate(&mut OsRng);
    let initiator = Initiator::new(SessionConfig {
        self_actor: "tf:actor:agent:example.com/i".into(),
        peer_hint: Some("tf:actor:agent:example.com/r".into()),
        identity_priv: i_id_priv(&i_id),
        identity_pub: i_id.public_key_bytes(),
        eph_seed: None,
        session_id_seed: None,
    });
    let responder = Responder::new(SessionConfig {
        self_actor: "tf:actor:agent:example.com/r".into(),
        peer_hint: None,
        identity_priv: i_id_priv(&r_id),
        identity_pub: r_id.public_key_bytes(),
        eph_seed: None,
        session_id_seed: None,
    });
    Pair { initiator, responder }
}

// Helper: Ed25519Signer doesn't expose its raw private bytes, so we go through
// from_bytes with a known seed. We'll cheat by re-creating with a fresh seed.
fn i_id_priv(_signer: &Ed25519Signer) -> [u8; 32] {
    // The dalek signer is from a 32-byte seed; for tests, we just generate
    // a random seed locally and synthesize a matching signer pair.
    use rand::RngCore;
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    seed
}

fn fresh_id() -> ([u8; 32], [u8; 32]) {
    use rand::RngCore;
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let signer = Ed25519Signer::from_bytes(&seed);
    (seed, signer.public_key_bytes())
}

fn make_pair_clean() -> Pair {
    let (ipriv, ipub) = fresh_id();
    let (rpriv, rpub) = fresh_id();
    let initiator = Initiator::new(SessionConfig {
        self_actor: "tf:actor:agent:example.com/i".into(),
        peer_hint: Some("tf:actor:agent:example.com/r".into()),
        identity_priv: ipriv,
        identity_pub: ipub,
        eph_seed: None,
        session_id_seed: None,
    });
    let responder = Responder::new(SessionConfig {
        self_actor: "tf:actor:agent:example.com/r".into(),
        peer_hint: None,
        identity_priv: rpriv,
        identity_pub: rpub,
        eph_seed: None,
        session_id_seed: None,
    });
    Pair { initiator, responder }
}

fn shake() -> (SessionState, SessionState) {
    let mut p = make_pair_clean();
    let hello_i = p.initiator.start().unwrap();
    let hello_r = p.responder.process_hello_i(hello_i).unwrap();
    let (auth, i_session) = p.initiator.process_hello_r(hello_r).unwrap();
    let r_session = p.responder.process_auth(auth).unwrap();
    (i_session, r_session)
}

#[test]
fn handshake_completes_with_matching_keys() {
    let (i, r) = shake();
    assert_eq!(i.generation, 0);
    assert_eq!(r.generation, 0);
    assert_eq!(i.send_key, r.recv_key);
    assert_eq!(i.recv_key, r.send_key);
    assert_eq!(i.session_id, r.session_id);
    assert_eq!(i.session_id.len(), 16);
}

#[test]
fn handshake_rejects_bad_version() {
    let mut p = make_pair_clean();
    let mut hello_i = p.initiator.start().unwrap();
    hello_i.version = 99;
    assert!(p.responder.process_hello_i(hello_i).is_err());
}

#[test]
fn handshake_rejects_bad_suite() {
    let mut p = make_pair_clean();
    let mut hello_i = p.initiator.start().unwrap();
    hello_i.suite = "snake-oil".into();
    assert!(p.responder.process_hello_i(hello_i).is_err());
}

#[test]
fn handshake_rejects_forged_responder_signature() {
    let mut p = make_pair_clean();
    let hello_i = p.initiator.start().unwrap();
    let mut hello_r = p.responder.process_hello_i(hello_i).unwrap();
    hello_r.signature = "AAAA".into();
    assert!(p.initiator.process_hello_r(hello_r).is_err());
}

#[test]
fn handshake_rejects_forged_initiator_signature() {
    let mut p = make_pair_clean();
    let hello_i = p.initiator.start().unwrap();
    let hello_r = p.responder.process_hello_i(hello_i).unwrap();
    let (mut auth, _is) = p.initiator.process_hello_r(hello_r).unwrap();
    auth.signature = "AAAA".into();
    assert!(p.responder.process_auth(auth).is_err());
}

#[test]
fn data_frame_round_trips() {
    let (mut i, mut r) = shake();
    let framed = i
        .encrypt(&SessionFrame::Data {
            payload: json!({ "hello": "world" }),
        })
        .unwrap();
    let decoded = r.decrypt(&framed).unwrap();
    match decoded {
        SessionFrame::Data { payload } => assert_eq!(payload, json!({ "hello": "world" })),
        other => panic!("expected data frame, got {:?}", other),
    }
}

#[test]
fn monotonic_sequence() {
    let (mut i, mut r) = shake();
    for n in 0..5 {
        let framed = i.encrypt(&SessionFrame::Data { payload: json!(n) }).unwrap();
        let decoded = r.decrypt(&framed).unwrap();
        match decoded {
            SessionFrame::Data { payload } => assert_eq!(payload, json!(n)),
            _ => panic!("data expected"),
        }
    }
    assert_eq!(i.send_seq, 5);
    assert_eq!(r.recv_seq, 5);
}

#[test]
fn out_of_order_rejected() {
    let (mut i, mut r) = shake();
    let f1 = i.encrypt(&SessionFrame::Data { payload: json!(1) }).unwrap();
    let f2 = i.encrypt(&SessionFrame::Data { payload: json!(2) }).unwrap();
    // Receiving f2 (seq=1) before f1 (seq=0) is rejected.
    assert!(matches!(r.decrypt(&f2), Err(SessionError::Generic(_))));
    // f1 still works.
    r.decrypt(&f1).unwrap();
    // Replaying f1 is also rejected.
    assert!(matches!(r.decrypt(&f1), Err(SessionError::Generic(_))));
}

#[test]
fn tampered_frame_rejected() {
    let (mut i, mut r) = shake();
    let mut framed = i
        .encrypt(&SessionFrame::Data { payload: json!("abc") })
        .unwrap();
    let last = framed.len() - 1;
    framed[last] ^= 0xff;
    assert!(matches!(r.decrypt(&framed), Err(SessionError::Aead(_))));
}

#[test]
fn rekey_rotates_and_resets_seqs() {
    let (mut i, mut r) = shake();
    let key_before = i.send_key;

    for n in 0..3 {
        let f = i.encrypt(&SessionFrame::Data { payload: json!(n) }).unwrap();
        r.decrypt(&f).unwrap();
    }

    let req_frame = i.request_rekey(None).unwrap();
    let decoded_req = r.decrypt(&req_frame).unwrap();
    let SessionFrame::RekeyReq { eph_pub } = decoded_req else {
        panic!("expected rekey-req");
    };
    let ack_frame = r.process_rekey_req(&eph_pub, None).unwrap();
    let decoded_ack = i.decrypt(&ack_frame).unwrap();
    let SessionFrame::RekeyAck { eph_pub: peer_eph_pub } = decoded_ack else {
        panic!("expected rekey-ack");
    };
    i.process_rekey_ack(&peer_eph_pub).unwrap();

    assert_eq!(i.generation, 1);
    assert_eq!(r.generation, 1);
    assert_eq!(i.send_seq, 0);
    assert_eq!(r.recv_seq, 0);
    assert_ne!(i.send_key, key_before);
    assert_eq!(i.send_key, r.recv_key);
    assert_eq!(i.recv_key, r.send_key);

    let f = i
        .encrypt(&SessionFrame::Data {
            payload: json!("after-rekey"),
        })
        .unwrap();
    let decoded = r.decrypt(&f).unwrap();
    match decoded {
        SessionFrame::Data { payload } => assert_eq!(payload, json!("after-rekey")),
        _ => panic!("data expected"),
    }
}

// Silence unused helpers when not in use.
#[allow(dead_code)]
fn _unused(_p: &Pair, _hi: HelloI, _hr: HelloR, _a: Auth) {}
