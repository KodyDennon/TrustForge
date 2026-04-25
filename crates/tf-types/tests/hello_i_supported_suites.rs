//! Rust accepts a TS-emitted HelloI (with `supported_suites` and `self_hint`)
//! and negotiates the suite from the offered list. Closes BUG-003.

use serde_json::json;
use tf_types::crypto_pq::ml_dsa_65_generate;
use tf_types::session::{
    HelloI, Responder, SessionConfig, SESSION_SUITE, SESSION_SUITE_HYBRID_ED25519_MLDSA65,
};

fn fresh_pub() -> [u8; 32] {
    use ed25519_dalek::SigningKey;
    use rand::RngCore;
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let signing = SigningKey::from_bytes(&seed);
    signing.verifying_key().to_bytes()
}

fn fresh_priv() -> [u8; 32] {
    use rand::RngCore;
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    seed
}

#[test]
fn rust_deserializes_ts_emitted_hello_i_with_supported_suites_and_self_hint() {
    // Wire shape that a TS initiator running B2 produces.
    let json = json!({
        "kind": "hello-i",
        "version": 0,
        "suite": SESSION_SUITE,
        "supported_suites": [SESSION_SUITE_HYBRID_ED25519_MLDSA65, SESSION_SUITE],
        "session_id": "AAAAAAAAAAAAAAAAAAAAAA==",
        "peer_hint": "tf:actor:service:example.com/server",
        "self_hint": "tf:actor:agent:example.com/the-claim",
        "eph_pub": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    });
    let parsed: HelloI = serde_json::from_value(json).expect("HelloI deserialize");
    assert_eq!(parsed.suite, SESSION_SUITE);
    assert_eq!(parsed.supported_suites.as_deref().map(|v| v.len()), Some(2));
    assert_eq!(
        parsed.self_hint.as_deref(),
        Some("tf:actor:agent:example.com/the-claim")
    );
}

#[test]
fn responder_picks_first_mutually_supported_suite() {
    // Initiator offers hybrid first, classical second. Responder accepts both.
    // Negotiation MUST pick hybrid (the initiator's preference).
    let priv_bytes = fresh_priv();
    use ed25519_dalek::SigningKey;
    let signing = SigningKey::from_bytes(&priv_bytes);
    let pub_bytes = signing.verifying_key().to_bytes();

    let (mldsa_priv, mldsa_pub) = ml_dsa_65_generate().expect("mldsa keygen");
    let mut responder = Responder::new(SessionConfig {
        self_actor: "tf:actor:service:example.com/server".into(),
        identity_priv: priv_bytes,
        identity_pub: pub_bytes,
        identity_mldsa_priv: Some(mldsa_priv),
        identity_mldsa_pub: Some(mldsa_pub),
        supported_suites: Some(vec![
            SESSION_SUITE.to_owned(),
            SESSION_SUITE_HYBRID_ED25519_MLDSA65.to_owned(),
        ]),
        ..Default::default()
    });

    let hello_i = HelloI {
        version: 0,
        suite: SESSION_SUITE_HYBRID_ED25519_MLDSA65.to_owned(),
        supported_suites: Some(vec![
            SESSION_SUITE_HYBRID_ED25519_MLDSA65.to_owned(),
            SESSION_SUITE.to_owned(),
        ]),
        session_id: tf_types::crypto::b64encode(&[0u8; 16]),
        peer_hint: String::new(),
        self_hint: None,
        eph_pub: tf_types::crypto::b64encode(&fresh_pub()),
    };

    let hello_r = responder.process_hello_i(hello_i).expect("process_hello_i");
    assert_eq!(
        hello_r.selected_suite.as_deref(),
        Some(SESSION_SUITE_HYBRID_ED25519_MLDSA65)
    );
    assert!(hello_r.signature_mldsa.is_some(), "hybrid responder must populate signature_mldsa");
    assert!(hello_r.ident_pub_mldsa.is_some(), "hybrid responder must populate ident_pub_mldsa");
}

#[test]
fn responder_rejects_when_no_mutually_supported_suite() {
    let priv_bytes = fresh_priv();
    use ed25519_dalek::SigningKey;
    let signing = SigningKey::from_bytes(&priv_bytes);
    let pub_bytes = signing.verifying_key().to_bytes();

    let mut responder = Responder::new(SessionConfig {
        self_actor: "tf:actor:service:example.com/server".into(),
        identity_priv: priv_bytes,
        identity_pub: pub_bytes,
        supported_suites: Some(vec![SESSION_SUITE.to_owned()]),
        ..Default::default()
    });

    let hello_i = HelloI {
        version: 0,
        suite: "snake-oil".into(),
        supported_suites: Some(vec!["snake-oil".into(), "snake-oil-2".into()]),
        session_id: tf_types::crypto::b64encode(&[0u8; 16]),
        peer_hint: String::new(),
        self_hint: None,
        eph_pub: tf_types::crypto::b64encode(&fresh_pub()),
    };

    assert!(responder.process_hello_i(hello_i).is_err());
}

#[test]
fn responder_falls_back_to_msg_suite_when_supported_suites_omitted() {
    let priv_bytes = fresh_priv();
    use ed25519_dalek::SigningKey;
    let signing = SigningKey::from_bytes(&priv_bytes);
    let pub_bytes = signing.verifying_key().to_bytes();

    let mut responder = Responder::new(SessionConfig {
        self_actor: "tf:actor:service:example.com/server".into(),
        identity_priv: priv_bytes,
        identity_pub: pub_bytes,
        ..Default::default()
    });

    let hello_i = HelloI {
        version: 0,
        suite: SESSION_SUITE.to_owned(),
        supported_suites: None,
        session_id: tf_types::crypto::b64encode(&[0u8; 16]),
        peer_hint: String::new(),
        self_hint: None,
        eph_pub: tf_types::crypto::b64encode(&fresh_pub()),
    };

    let hello_r = responder.process_hello_i(hello_i).expect("process_hello_i");
    assert_eq!(hello_r.selected_suite.as_deref(), Some(SESSION_SUITE));
}
