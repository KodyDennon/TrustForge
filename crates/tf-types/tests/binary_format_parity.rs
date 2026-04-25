//! Rust side of the .tfbundle / .tfpkt binary-format parity suite. Loads
//! `conformance/binary-format-vectors.yaml` and asserts that
//! `write_tfbundle` / `write_tfpkt` produce the exact `expected_hex`
//! byte sequence for every fixture. The TS mirror lives in
//! `tools/tf-conformance/tests/runner.test.ts` (the
//! `runBinaryFormatVectors` runner) and consumes the same vectors.
//!
//! Byte-level parity here is the wire-format guarantee that lets a
//! .tfpkt minted by Rust be parsed by TS (or any other language with a
//! conformant implementation), and vice versa.

use std::fs;

use serde::Deserialize;

use tf_types::binary_format::{write_tfbundle, write_tfpkt};
use tf_types::generated::Packet;

#[derive(Deserialize)]
struct BundleFixture {
    id: String,
    input_yaml: String,
    #[serde(default)]
    signature_hex: Option<String>,
    expected_hex: String,
}

#[derive(Deserialize)]
struct PacketFixture {
    id: String,
    input_yaml: String,
    expected_hex: String,
}

#[derive(Deserialize)]
struct VectorFile {
    tfbundle: Vec<BundleFixture>,
    tfpkt: Vec<PacketFixture>,
}

fn from_hex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[test]
fn binary_format_vectors_round_trip() {
    let path = format!(
        "{}/../../conformance/binary-format-vectors.yaml",
        env!("CARGO_MANIFEST_DIR")
    );
    let raw =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {}", path, e));
    let file: VectorFile =
        serde_yaml::from_str(&raw).expect("parse binary-format-vectors.yaml");

    assert_eq!(file.tfbundle.len(), 4, "expected 4 tfbundle fixtures");
    assert_eq!(file.tfpkt.len(), 4, "expected 4 tfpkt fixtures");

    for f in &file.tfbundle {
        // Parse the inner YAML payload as a generic JSON value so the
        // canonical (BTreeMap-sorted) encoder kicks in — which is the
        // same path real callers use for ProofBundle / ProofBundleEncrypted.
        let body: serde_json::Value =
            serde_yaml::from_str(&f.input_yaml).expect("parse bundle input_yaml");
        let sig: Option<Vec<u8>> = f.signature_hex.as_deref().map(from_hex);
        let bytes =
            write_tfbundle(&body, sig.as_deref()).expect("write_tfbundle");
        let got = to_hex(&bytes);
        assert_eq!(
            got, f.expected_hex,
            "tfbundle.{} hex mismatch",
            f.id
        );
    }

    for f in &file.tfpkt {
        // Deserialize into the typed Packet struct — that's the
        // production code path. The BTreeMap-via-serde_json::Value
        // canonicalization step inside `cbor_encode` ensures the
        // emitted bytes match the TS encoder's sorted-key output.
        let pkt: Packet =
            serde_yaml::from_str(&f.input_yaml).expect("parse packet input_yaml");
        let bytes = write_tfpkt(&pkt).expect("write_tfpkt");
        let got = to_hex(&bytes);
        assert_eq!(got, f.expected_hex, "tfpkt.{} hex mismatch", f.id);
    }
}
