//! Deterministic JSON serialization compatible with the TypeScript
//! implementation in `tools/tf-types-ts/src/core/canonical.ts`.
//!
//! Rules:
//!   * Object keys are sorted by UTF-8 byte order of their NFC-normalized
//!     form. (Rust's `String::cmp` compares underlying UTF-8 bytes; the
//!     TS implementation uses an explicit UTF-8 byte comparator instead
//!     of JS's UTF-16 code-unit `<`.)
//!   * All string values are NFC-normalized.
//!   * Finite integers emit as integers (no `.0`); finite non-integer numbers
//!     emit via Rust's shortest round-trip representation, matching the
//!     `serde_json` defaults which in turn match JavaScript's `String(n)`.
//!   * `-0` is emitted as `0`.
//!   * `NaN`, `±Infinity` are rejected.
//!   * No whitespace anywhere in the output.
//!
//! Byte-for-byte parity with the TypeScript implementation is enforced by
//! `conformance/canonical-vectors.yaml` and
//! `conformance/cross-language-signature-vectors.yaml`.

use std::fmt::Write;

use serde_json::{Map, Value};

#[derive(Debug, thiserror::Error)]
pub enum CanonicalJsonError {
    #[error("cannot canonicalize non-finite number: {0}")]
    NonFinite(f64),
}

pub fn canonicalize(value: &Value) -> Result<String, CanonicalJsonError> {
    let mut out = String::new();
    encode(value, &mut out)?;
    Ok(out)
}

fn encode(v: &Value, out: &mut String) -> Result<(), CanonicalJsonError> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                write!(out, "{}", i).unwrap();
            } else if let Some(u) = n.as_u64() {
                write!(out, "{}", u).unwrap();
            } else if let Some(f) = n.as_f64() {
                if !f.is_finite() {
                    return Err(CanonicalJsonError::NonFinite(f));
                }
                if f == 0.0 {
                    out.push('0');
                } else if f.fract() == 0.0 && f.abs() < 1e16 {
                    write!(out, "{}", f as i64).unwrap();
                } else {
                    write!(out, "{}", f).unwrap();
                }
            }
        }
        Value::String(s) => write_json_string(&nfc(s), out),
        Value::Array(xs) => {
            out.push('[');
            for (i, x) in xs.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                encode(x, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            let mut entries: Vec<(String, &Value)> = map.iter().map(|(k, v)| (nfc(k), v)).collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            for (i, (k, v)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json_string(k, out);
                out.push(':');
                encode(v, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn nfc(s: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    UnicodeNormalization::nfc(s).collect()
}

fn write_json_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                write!(out, "\\u{:04x}", c as u32).unwrap();
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Convenience for &serde_json::Map.
pub fn canonicalize_map(map: &Map<String, Value>) -> Result<String, CanonicalJsonError> {
    canonicalize(&Value::Object(map.clone()))
}
