//! End-to-end Rust↔Rust hybrid handshake. Both peers carry an ml-dsa-65
//! key; the responder selects the hybrid suite; both transcripts are
//! signed in parallel with ed25519 + ml-dsa-65; tampering either
//! signature alone fails the handshake.

use ed25519_dalek::SigningKey;
use rand::RngCore;
use tf_types::crypto_pq::ml_dsa_65_generate;
use tf_types::session::{
    Initiator, Responder, SessionConfig, SESSION_SUITE_HYBRID_ED25519_MLDSA65,
};

fn fresh_id() -> ([u8; 32], [u8; 32]) {
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let signing = SigningKey::from_bytes(&seed);
    (seed, signing.verifying_key().to_bytes())
}

#[test]
fn hybrid_handshake_round_trip() {
    let (ipriv, ipub) = fresh_id();
    let (rpriv, rpub) = fresh_id();
    let (i_mldsa_sk, i_mldsa_pk) = ml_dsa_65_generate().expect("i mldsa");
    let (r_mldsa_sk, r_mldsa_pk) = ml_dsa_65_generate().expect("r mldsa");

    let mut initiator = Initiator::new(SessionConfig {
        self_actor: "tf:actor:agent:example.com/i".into(),
        peer_hint: Some("tf:actor:service:example.com/r".into()),
        identity_priv: ipriv,
        identity_pub: ipub,
        preferred_suite: Some(SESSION_SUITE_HYBRID_ED25519_MLDSA65.to_owned()),
        identity_mldsa_priv: Some(i_mldsa_sk.clone()),
        identity_mldsa_pub: Some(i_mldsa_pk),
        ..Default::default()
    });
    let mut responder = Responder::new(SessionConfig {
        self_actor: "tf:actor:service:example.com/r".into(),
        identity_priv: rpriv,
        identity_pub: rpub,
        identity_mldsa_priv: Some(r_mldsa_sk),
        identity_mldsa_pub: Some(r_mldsa_pk),
        ..Default::default()
    });

    let hello_i = initiator.start().expect("start");
    assert_eq!(
        hello_i.suite, SESSION_SUITE_HYBRID_ED25519_MLDSA65,
        "initiator advertises hybrid suite as preferred"
    );

    let hello_r = responder.process_hello_i(hello_i).expect("process_hello_i");
    assert_eq!(
        hello_r.selected_suite.as_deref(),
        Some(SESSION_SUITE_HYBRID_ED25519_MLDSA65)
    );
    assert!(hello_r.signature_mldsa.is_some());
    assert!(hello_r.ident_pub_mldsa.is_some());

    let (auth, init_session) = initiator.process_hello_r(hello_r).expect("process_hello_r");
    assert!(auth.signature_mldsa.is_some(), "initiator Auth must carry mldsa sig");
    assert!(auth.ident_pub_mldsa.is_some());

    let resp_session = responder.process_auth(auth).expect("process_auth");
    // Both peerActor URIs are the key-derived form (post-B1).
    assert!(init_session.peer_actor.starts_with("tf:actor:process:key/"));
    assert!(resp_session.peer_actor.starts_with("tf:actor:process:key/"));
    // self_actor stays the configured human-readable URI on both sides.
    assert_eq!(init_session.self_actor, "tf:actor:agent:example.com/i");
    assert_eq!(resp_session.self_actor, "tf:actor:service:example.com/r");
}

#[test]
fn hybrid_handshake_rejects_tampered_mldsa_signature() {
    let (ipriv, ipub) = fresh_id();
    let (rpriv, rpub) = fresh_id();
    let (i_mldsa_sk, i_mldsa_pk) = ml_dsa_65_generate().expect("i mldsa");
    let (r_mldsa_sk, r_mldsa_pk) = ml_dsa_65_generate().expect("r mldsa");

    let mut initiator = Initiator::new(SessionConfig {
        self_actor: "tf:actor:agent:example.com/i".into(),
        identity_priv: ipriv,
        identity_pub: ipub,
        preferred_suite: Some(SESSION_SUITE_HYBRID_ED25519_MLDSA65.to_owned()),
        identity_mldsa_priv: Some(i_mldsa_sk),
        identity_mldsa_pub: Some(i_mldsa_pk),
        ..Default::default()
    });
    let mut responder = Responder::new(SessionConfig {
        self_actor: "tf:actor:service:example.com/r".into(),
        identity_priv: rpriv,
        identity_pub: rpub,
        identity_mldsa_priv: Some(r_mldsa_sk),
        identity_mldsa_pub: Some(r_mldsa_pk),
        ..Default::default()
    });

    let hello_i = initiator.start().expect("start");
    let mut hello_r = responder.process_hello_i(hello_i).expect("process_hello_i");
    // Flip a byte in the responder's mldsa signature; the initiator MUST
    // refuse the handshake even though ed25519 still verifies.
    let bad = hello_r
        .signature_mldsa
        .as_mut()
        .expect("hybrid populates signature_mldsa");
    let mut sig_bytes = tf_types::crypto::b64decode(bad).expect("b64");
    sig_bytes[0] ^= 0x01;
    *bad = tf_types::crypto::b64encode(&sig_bytes);
    assert!(initiator.process_hello_r(hello_r).is_err());
}
