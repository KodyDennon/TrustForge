use tf_session::{attach_initiator, attach_responder};
use tf_types::session::{SessionConfig, SessionFrame};
use tf_types::crypto::Ed25519Signer;
use tokio::io::duplex;
use std::sync::Arc;
use tokio::sync::mpsc;

fn fresh_id() -> ([u8; 32], [u8; 32]) {
    use rand::RngCore;
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let signer = Ed25519Signer::from_bytes(&seed);
    (seed, signer.public_key_bytes())
}

#[tokio::test]
async fn test_carrier_handshake_and_data() {
    let (ipriv, ipub) = fresh_id();
    let (rpriv, rpub) = fresh_id();

    let iconfig = SessionConfig {
        self_actor: "tf:actor:agent:example.com/i".into(),
        peer_hint: Some("tf:actor:agent:example.com/r".into()),
        identity_priv: ipriv,
        identity_pub: ipub,
        ..Default::default()
    };
    let rconfig = SessionConfig {
        self_actor: "tf:actor:agent:example.com/r".into(),
        identity_priv: rpriv,
        identity_pub: rpub,
        ..Default::default()
    };

    let (client, server) = duplex(1024);

    let i_handle = tokio::spawn(async move {
        attach_initiator(client, iconfig).await.unwrap()
    });

    let r_handle = tokio::spawn(async move {
        attach_responder(server, rconfig).await.unwrap()
    });

    let (i_ep, r_ep) = tokio::try_join!(i_handle, r_handle).unwrap();

    // Handshake successful if we got here.
    let expected_i_uri = tf_types::actor_id::derive_peer_actor(&ipub).unwrap();
    let expected_r_uri = tf_types::actor_id::derive_peer_actor(&rpub).unwrap();

    assert_eq!(i_ep.peer_actor().await, expected_r_uri);
    assert_eq!(r_ep.peer_actor().await, expected_i_uri);

    // Test data round-trip
    let (tx, mut rx) = mpsc::unbounded_channel();
    r_ep.on_frame(move |f| {
        let _ = tx.send(f);
    }).await;

    let test_payload = serde_json::json!({"hello": "from initiator"});
    i_ep.send(SessionFrame::Data {
        payload: test_payload.clone(),
    }).await.unwrap();

    let received = rx.recv().await.unwrap();
    match received {
        SessionFrame::Data { payload } => assert_eq!(payload, test_payload),
        _ => panic!("expected data frame"),
    }
}
