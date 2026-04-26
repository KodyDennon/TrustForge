//! Rust side of the binary-framing parity suite.

use std::fs;
use std::path::PathBuf;

use serde::Deserialize;

use tf_types::format::{
    read_tflog, read_tfproof, write_tflog, write_tfproof, FormatError, TFLOG_MAGIC, TFPROOF_MAGIC,
};
use tf_types::generated::{proof_bundle::ProofBundle, proof_event::ProofEvent};

#[derive(Deserialize)]
struct VectorsFile {
    tflog: Vec<TflogCase>,
    tfproof: Vec<TfproofCase>,
}

#[derive(Deserialize)]
struct TflogCase {
    name: String,
    events: Vec<ProofEvent>,
    expected_hex: Option<String>,
}

#[derive(Deserialize)]
struct TfproofCase {
    name: String,
    bundle: ProofBundle,
    signature_hex: String,
    expected_hex: Option<String>,
}

fn load_vectors() -> VectorsFile {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("conformance")
        .join("framing-vectors.yaml");
    let raw = fs::read_to_string(&path).expect("read framing-vectors.yaml");
    serde_yaml::from_str(&raw).expect("parse framing-vectors.yaml")
}

fn hex_of(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn tflog_round_trips() {
    for c in &load_vectors().tflog {
        let framed = write_tflog(&c.events).expect("write");
        assert_eq!(&framed[..8], TFLOG_MAGIC, "{} magic", c.name);
        let parsed = read_tflog(&framed).expect("read");
        assert_eq!(parsed.len(), c.events.len(), "{} event count", c.name);
        let reframed = write_tflog(&parsed).expect("re-write");
        assert_eq!(hex_of(&reframed), hex_of(&framed), "{} byte parity", c.name);
        if let Some(expected) = &c.expected_hex {
            assert_eq!(
                &hex_of(&framed),
                expected,
                "{} cross-language byte parity",
                c.name
            );
        }
    }
}

#[test]
fn tflog_rejects_bad_magic() {
    let bad = vec![0u8; 8];
    let err = read_tflog(&bad).unwrap_err();
    assert!(matches!(err, FormatError::BadMagic(_)));
}

#[test]
fn tflog_rejects_truncated_frame() {
    let vectors = load_vectors();
    let framed = write_tflog(&vectors.tflog[0].events).expect("write");
    let chopped = &framed[..framed.len() - 1];
    assert!(read_tflog(chopped).is_err());
}

#[test]
fn tfproof_round_trips() {
    for c in &load_vectors().tfproof {
        let sig = from_hex(&c.signature_hex);
        let framed = write_tfproof(&c.bundle, &sig).expect("write");
        assert_eq!(&framed[..8], TFPROOF_MAGIC, "{} magic", c.name);
        let parsed = read_tfproof(&framed).expect("read");
        assert_eq!(
            hex_of(&parsed.signature),
            c.signature_hex,
            "{} signature",
            c.name
        );
        let reframed = write_tfproof(&parsed.bundle, &parsed.signature).expect("re-write");
        assert_eq!(hex_of(&reframed), hex_of(&framed), "{} byte parity", c.name);
        if let Some(expected) = &c.expected_hex {
            assert_eq!(
                &hex_of(&framed),
                expected,
                "{} cross-language byte parity",
                c.name
            );
        }
    }
}

#[test]
fn tfproof_rejects_bad_magic() {
    let bad = vec![0u8; 16];
    let err = read_tfproof(&bad).unwrap_err();
    assert!(matches!(err, FormatError::BadMagic(_)));
}
