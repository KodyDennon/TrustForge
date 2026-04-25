//! Rust side of the canonical-JSON parity suite. Loads
//! `canonical-vectors.yaml` from the repo root and asserts the Rust
//! `canonicalize` output matches the `output` string for every vector.
//! Byte-for-byte parity with the TS implementation is what makes signing
//! cross-language later.

use std::fs;

use serde::Deserialize;

use tf_types::canonical::canonicalize;

#[derive(Deserialize)]
struct Vector {
    name: String,
    input: serde_json::Value,
    output: String,
}

#[derive(Deserialize)]
struct File {
    vectors: Vec<Vector>,
}

#[test]
fn parity_against_shared_vectors() {
    let path = format!("{}/../../conformance/canonical-vectors.yaml", env!("CARGO_MANIFEST_DIR"));
    let raw = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {}", path, e));
    let file: File = serde_yaml::from_str(&raw).expect("parse canonical-vectors.yaml");
    for v in &file.vectors {
        let got = canonicalize(&v.input).expect("canonicalize");
        assert_eq!(got, v.output, "vector {}", v.name);
    }
}
