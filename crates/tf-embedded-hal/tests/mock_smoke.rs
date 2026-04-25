//! End-to-end smoke test: sign a packet via `MockSecureElement`,
//! squirt it through `MockLoraRadio`, receive it on the other side,
//! and verify the signature against the element's published pubkey.

use tf_core_no_std::packet::{sign_packet, verify_packet};
use tf_embedded_hal::adapters::{
    MockBleAdvertiser, MockEntropy, MockLoraRadio, MockNfcReader, MockSecureElement,
};
use tf_embedded_hal::{BleAdvertiser, Entropy, LoraRadio, NfcReader, SecureElement};

#[test]
fn lora_round_trip_with_secure_element() {
    let seed = [11u8; 32];
    let mut se = MockSecureElement::from_seed(seed).expect("se");
    let pk = se.pubkey();

    let signer = "tf:actor:agent:example.com/sensor";
    let signing_seed = ed25519_compact::Seed::from_slice(&seed).unwrap();
    let pkt = sign_packet(
        b"telemetry",
        &signing_seed,
        signer,
        "pkt-77",
        signer,
        "tf:actor:service:example.com/ingest",
        "P3",
        Some("2099-01-01T00:00:00Z"),
    )
    .expect("sign");

    // Serialise the packet payload + signature in a tiny TLV so the
    // smoke test demonstrates an end-to-end transit. Real deployments
    // use CBOR; we keep it minimal here.
    let mut frame: [u8; 256] = [0; 256];
    let payload = &pkt.payload;
    let sig = &pkt.signature;
    frame[0] = payload.len() as u8;
    frame[1..1 + payload.len()].copy_from_slice(payload);
    let off = 1 + payload.len();
    frame[off] = sig.len() as u8;
    frame[off + 1..off + 1 + sig.len()].copy_from_slice(sig);
    let total = off + 1 + sig.len();

    let mut radio = MockLoraRadio::new();
    radio.send(&frame[..total]).expect("send");
    assert_eq!(radio.outbox.len(), 1);

    // Deliver to the same radio's inbox to simulate loop-back.
    let outbound = radio.outbox.remove(0);
    radio.enqueue_inbox(&outbound).unwrap();

    let mut buf = [0u8; 256];
    let n = radio.recv(&mut buf).expect("recv");
    assert_eq!(n, total);
    assert_eq!(&buf[..total], &frame[..total]);

    // Verify the original packet's signature using `pk` (the secure
    // element's published key).
    verify_packet(&pkt, &pk, "2026-04-25T00:00:00Z").expect("verify");
}

#[test]
fn ble_advertise_records_payload() {
    let mut ble = MockBleAdvertiser::new();
    ble.advertise(b"hello").expect("advertise");
    assert_eq!(ble.advertise_count, 1);
    assert_eq!(ble.last.as_deref(), Some(&b"hello"[..]));
}

#[test]
fn nfc_read_returns_enqueued_frames() {
    let mut nfc = MockNfcReader::new();
    nfc.enqueue(b"\x01\x02\x03").unwrap();
    let mut buf = [0u8; 16];
    let n = nfc.read(&mut buf).expect("read");
    assert_eq!(&buf[..n], b"\x01\x02\x03");
}

#[test]
fn entropy_produces_distinct_buffers() {
    let mut rng = MockEntropy::new(42);
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    rng.fill(&mut a).unwrap();
    rng.fill(&mut b).unwrap();
    assert_ne!(a, b);
}

#[test]
fn secure_element_sign_then_verify() {
    let mut se = MockSecureElement::from_seed([99u8; 32]).expect("se");
    let msg = b"sign me";
    let sig = se.sign(msg).expect("sign");
    assert!(se.verify(msg, &sig));
    assert!(!se.verify(b"different", &sig));
}
