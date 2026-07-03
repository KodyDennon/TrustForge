#![allow(clippy::doc_lazy_continuation)]
//! Binary container formats — Rust mirror of TS `binary-format.ts`.
//!
//!   .tfbundle  — sealed/serialized proof bundle, L4/L5 capable.
//!      magic     = "TFBND" 0x01 0x00 0x00            (8 bytes)
//!      body_len  = u32 BE
//!      body      = CBOR-encoded ProofBundleEncrypted | ProofBundle
//!      sig_len   = u32 BE   (0 when unsigned)
//!      signature = sig_len bytes (raw ed25519)
//!
//!   .tfpkt     — packet-on-the-wire envelope.
//!      magic     = "TFPKT" 0x01 0x00 0x00            (8 bytes)
//!      body_len  = u32 BE
//!      body      = CBOR-encoded Packet
//!
//! The Rust encoder must produce byte-identical output to the TS
//! encoder for the same canonical input — verified by
//! `conformance/binary-format-vectors.yaml`.
//!
//! --- CBOR DETERMINISM (READ BEFORE EDITING) ---
//!
//! For wire-level parity with the TS encoder (cbor-x with sorted keys
//! + `variableMapSize: true`), the Rust encoder converts through
//! `serde_json::Value` first. `serde_json::Value::Object` is a
//! `BTreeMap`, so its keys are emitted in lexicographic byte order
//! when ciborium walks it — which matches RFC 8949 §4.2.3 deterministic
//! encoding and matches the TS side. Without this intermediate, a
//! native `#[derive(Serialize)]` struct would emit fields in
//! declaration order and break parity.
//!
//! Yes, this costs one extra ser/deser per encode. The packets are
//! small (typical .tfpkt <1 KiB) and constrained-mode use cases never
//! hot-loop the encoder, so the trade for a stable wire format is
//! correct. Do NOT remove the round-trip without first updating
//! `conformance/binary-format-vectors.yaml` and the matching TS test.

use crate::generated::Packet;
use ciborium::value::Value as CborValue;
use serde::{de::DeserializeOwned, Serialize};

pub const TFBUNDLE_MAGIC: [u8; 8] = [0x54, 0x46, 0x42, 0x4e, 0x44, 0x01, 0x00, 0x00];
pub const TFPKT_MAGIC: [u8; 8] = [0x54, 0x46, 0x50, 0x4b, 0x54, 0x01, 0x00, 0x00];

#[derive(Debug, thiserror::Error)]
pub enum BinaryFormatError {
    #[error("bad magic")]
    BadMagic,
    #[error("truncated at offset {0}")]
    Truncated(usize),
    #[error("cbor: {0}")]
    Cbor(String),
    #[error("length out of range: {0}")]
    LengthOutOfRange(u64),
}

fn put_u32_be(buf: &mut Vec<u8>, n: usize) -> Result<(), BinaryFormatError> {
    if n > u32::MAX as usize {
        return Err(BinaryFormatError::LengthOutOfRange(n as u64));
    }
    let n = n as u32;
    buf.extend_from_slice(&n.to_be_bytes());
    Ok(())
}

fn read_u32_be(buf: &[u8], off: usize) -> Result<u32, BinaryFormatError> {
    if off + 4 > buf.len() {
        return Err(BinaryFormatError::Truncated(off));
    }
    Ok(u32::from_be_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
    ]))
}

fn canonicalize_json(v: serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match v {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> = map
                .into_iter()
                .map(|(k, val)| (k, canonicalize_json(val)))
                .collect();
            entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            let mut out = serde_json::Map::with_capacity(entries.len());
            for (k, val) in entries {
                out.insert(k, val);
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.into_iter().map(canonicalize_json).collect()),
        other => other,
    }
}

fn cbor_encode<T: Serialize>(v: &T) -> Result<Vec<u8>, BinaryFormatError> {
    // RFC 8949 §4.2.3 deterministic encoding. We canonicalize through a
    // `serde_json::Value` intermediate then explicitly sort all object
    // keys lexicographically — relying on `serde_json::Map`'s default
    // BTreeMap backing isn't safe because any workspace dep may pull in
    // `serde_json` with the `preserve_order` feature, which silently
    // switches the backing map to `IndexMap` and breaks parity.
    let json_value: serde_json::Value =
        serde_json::to_value(v).map_err(|e| BinaryFormatError::Cbor(e.to_string()))?;
    let canonical = canonicalize_json(json_value);
    let mut out = Vec::new();
    ciborium::ser::into_writer(&canonical, &mut out)
        .map_err(|e| BinaryFormatError::Cbor(e.to_string()))?;
    Ok(out)
}

fn cbor_decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, BinaryFormatError> {
    ciborium::de::from_reader(bytes).map_err(|e| BinaryFormatError::Cbor(e.to_string()))
}

/* -------------------------------------------------------------------------- */
/*  .tfbundle                                                                  */
/* -------------------------------------------------------------------------- */

pub fn write_tfbundle<T: Serialize>(
    body: &T,
    signature: Option<&[u8]>,
) -> Result<Vec<u8>, BinaryFormatError> {
    let body_bytes = cbor_encode(body)?;
    let mut out = Vec::with_capacity(TFBUNDLE_MAGIC.len() + 4 + body_bytes.len() + 4);
    out.extend_from_slice(&TFBUNDLE_MAGIC);
    put_u32_be(&mut out, body_bytes.len())?;
    out.extend_from_slice(&body_bytes);
    let sig = signature.unwrap_or(&[]);
    put_u32_be(&mut out, sig.len())?;
    out.extend_from_slice(sig);
    Ok(out)
}

#[derive(Debug)]
pub struct TfbundleParts {
    /// CBOR-decoded body as a generic Value; callers can deserialize
    /// into a typed struct via `serde_json::to_value` round-trip if
    /// they don't want to call `read_tfbundle_typed::<T>` directly.
    pub body: CborValue,
    pub signature: Vec<u8>,
    pub body_bytes: Vec<u8>,
}

pub fn read_tfbundle(buf: &[u8]) -> Result<TfbundleParts, BinaryFormatError> {
    if buf.len() < TFBUNDLE_MAGIC.len() {
        return Err(BinaryFormatError::BadMagic);
    }
    if buf[..TFBUNDLE_MAGIC.len()] != TFBUNDLE_MAGIC {
        return Err(BinaryFormatError::BadMagic);
    }
    let mut off = TFBUNDLE_MAGIC.len();
    let body_len = read_u32_be(buf, off)? as usize;
    off += 4;
    if off + body_len > buf.len() {
        return Err(BinaryFormatError::Truncated(off));
    }
    let body_bytes = buf[off..off + body_len].to_vec();
    let body: CborValue = cbor_decode(&body_bytes)?;
    off += body_len;
    let sig_len = read_u32_be(buf, off)? as usize;
    off += 4;
    if off + sig_len > buf.len() {
        return Err(BinaryFormatError::Truncated(off));
    }
    let signature = buf[off..off + sig_len].to_vec();
    Ok(TfbundleParts {
        body,
        signature,
        body_bytes,
    })
}

/// Read a .tfbundle and deserialize the body into a typed `T`.
pub fn read_tfbundle_typed<T: DeserializeOwned>(
    buf: &[u8],
) -> Result<(T, Vec<u8>), BinaryFormatError> {
    let parts = read_tfbundle(buf)?;
    let body: T = cbor_decode(&parts.body_bytes)?;
    Ok((body, parts.signature))
}

/* -------------------------------------------------------------------------- */
/*  .tfpkt                                                                     */
/* -------------------------------------------------------------------------- */

pub fn write_tfpkt(packet: &Packet) -> Result<Vec<u8>, BinaryFormatError> {
    let body_bytes = cbor_encode(packet)?;
    let mut out = Vec::with_capacity(TFPKT_MAGIC.len() + 4 + body_bytes.len());
    out.extend_from_slice(&TFPKT_MAGIC);
    put_u32_be(&mut out, body_bytes.len())?;
    out.extend_from_slice(&body_bytes);
    Ok(out)
}

pub fn read_tfpkt(buf: &[u8]) -> Result<Packet, BinaryFormatError> {
    if buf.len() < TFPKT_MAGIC.len() {
        return Err(BinaryFormatError::BadMagic);
    }
    if buf[..TFPKT_MAGIC.len()] != TFPKT_MAGIC {
        return Err(BinaryFormatError::BadMagic);
    }
    let mut off = TFPKT_MAGIC.len();
    let body_len = read_u32_be(buf, off)? as usize;
    off += 4;
    if off + body_len > buf.len() {
        return Err(BinaryFormatError::Truncated(off));
    }
    cbor_decode(&buf[off..off + body_len])
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn tfbundle_round_trip_unsigned() {
        let body = json!({
            "bundle_version": "1",
            "events": [],
        });
        let buf = write_tfbundle(&body, None).expect("write");
        assert_eq!(buf[..TFBUNDLE_MAGIC.len()], TFBUNDLE_MAGIC);
        let parts = read_tfbundle(&buf).expect("read");
        assert_eq!(parts.signature.len(), 0);
        // Round-trip the CBOR body back through serde_json.
        let mut serialised = Vec::new();
        ciborium::ser::into_writer(&parts.body, &mut serialised).unwrap();
        // Re-decode as a typed Value to assert structure.
        let decoded: serde_json::Value = ciborium::de::from_reader(serialised.as_slice()).unwrap();
        assert_eq!(decoded["bundle_version"], "1");
    }

    #[test]
    fn tfbundle_round_trip_with_signature() {
        let body = json!({"bundle_version": "1", "events": []});
        let signature = vec![0xaa; 64];
        let buf = write_tfbundle(&body, Some(&signature)).expect("write");
        let parts = read_tfbundle(&buf).expect("read");
        assert_eq!(parts.signature, signature);
    }

    #[test]
    fn tfbundle_bad_magic_rejected() {
        let buf = b"NOT-A-BUNDLE\x00\x00\x00\x00";
        let err = read_tfbundle(buf).unwrap_err();
        assert!(matches!(err, BinaryFormatError::BadMagic));
    }

    #[test]
    fn tfpkt_round_trip_envelope() {
        // Build a minimal Packet via serde_json so we don't depend on
        // sign_packet here; the format itself is what's under test.
        let pkt: Packet = serde_json::from_value(json!({
            "packet_version": "1",
            "packet_id": "pkt-roundtrip",
            "source": "tf:actor:agent:example.com/x",
            "destination": "tf:actor:service:example.com/d",
            "priority": "P3",
            "created_at": "2026-04-24T12:00:00Z",
            "encoding": "cbor",
            "compression": "none",
            "payload": "AAAA",
            "signature": {
                "algorithm": "ed25519",
                "signer": "tf:actor:agent:example.com/x",
                "signature": "AAAA",
            },
        }))
        .expect("packet");
        let buf = write_tfpkt(&pkt).expect("write");
        assert_eq!(buf[..TFPKT_MAGIC.len()], TFPKT_MAGIC);
        let decoded = read_tfpkt(&buf).expect("read");
        assert_eq!(decoded.packet_id, pkt.packet_id);
    }

    #[test]
    fn tfpkt_truncated_body_rejected() {
        let pkt: Packet = serde_json::from_value(json!({
            "packet_version": "1",
            "packet_id": "pkt-trunc",
            "source": "tf:actor:agent:example.com/x",
            "destination": "tf:actor:service:example.com/d",
            "priority": "P3",
            "created_at": "2026-04-24T12:00:00Z",
            "encoding": "cbor",
            "compression": "none",
            "payload": "AAAA",
            "signature": {
                "algorithm": "ed25519",
                "signer": "tf:actor:agent:example.com/x",
                "signature": "AAAA",
            },
        }))
        .expect("packet");
        let buf = write_tfpkt(&pkt).expect("write");
        let chopped = &buf[..buf.len() - 5];
        let err = read_tfpkt(chopped).unwrap_err();
        assert!(matches!(err, BinaryFormatError::Truncated(_)));
    }
}
