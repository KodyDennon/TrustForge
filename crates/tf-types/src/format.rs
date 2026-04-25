//! Binary framing for `.tflog` and `.tfproof`. Matches
//! `tools/tf-types-ts/src/core/format.ts` byte-for-byte via
//! `conformance/framing-vectors.yaml`.
//!
//! `.tflog`  — append-only log of proof events.
//!   header  = "TFLOG\x01\x00\x00"   (8 bytes)
//!   frames  = u32 BE length + canonical-JSON event bytes (repeat)
//!
//! `.tfproof` — signed bundle container.
//!   header  = "TFPROOF\x01"           (8 bytes)
//!   body    = u32 BE length + canonical-JSON bundle bytes
//!   trailer = u32 BE length + raw signature bytes

use serde_json::Value;

use crate::canonical::canonicalize;
use crate::generated::proof_bundle::ProofBundle;
use crate::generated::proof_event::ProofEvent;

pub const TFLOG_MAGIC: &[u8; 8] = b"TFLOG\x01\x00\x00";
pub const TFPROOF_MAGIC: &[u8; 8] = b"TFPROOF\x01";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FormatError {
    #[error("unexpected end of input at offset {0}")]
    Truncated(usize),
    #[error("bad magic header at offset {0}")]
    BadMagic(usize),
    #[error("length prefix {1} exceeds remaining bytes at offset {0}")]
    BadLength(usize, u32),
    #[error("canonical JSON error: {0}")]
    Canonical(String),
    #[error("serde error: {0}")]
    Serde(String),
    #[error("utf-8 error: {0}")]
    Utf8(String),
}

fn put_u32_be(buf: &mut Vec<u8>, n: usize) -> Result<(), FormatError> {
    let n = u32::try_from(n).map_err(|_| FormatError::BadLength(buf.len(), u32::MAX))?;
    buf.extend_from_slice(&n.to_be_bytes());
    Ok(())
}

fn read_u32_be(buf: &[u8], off: usize) -> Result<u32, FormatError> {
    if off + 4 > buf.len() {
        return Err(FormatError::Truncated(off));
    }
    let arr: [u8; 4] = buf[off..off + 4].try_into().unwrap();
    Ok(u32::from_be_bytes(arr))
}

// ---------- .tflog ----------

pub fn write_tflog(events: &[ProofEvent]) -> Result<Vec<u8>, FormatError> {
    let mut buf = Vec::with_capacity(256);
    buf.extend_from_slice(TFLOG_MAGIC);
    for e in events {
        let json = serde_json::to_value(e).map_err(|e| FormatError::Serde(e.to_string()))?;
        let body = canonicalize(&json).map_err(|e| FormatError::Canonical(e.to_string()))?;
        let bytes = body.into_bytes();
        put_u32_be(&mut buf, bytes.len())?;
        buf.extend_from_slice(&bytes);
    }
    Ok(buf)
}

pub fn append_tflog(existing: &mut Vec<u8>, event: &ProofEvent) -> Result<(), FormatError> {
    if existing.is_empty() {
        existing.extend_from_slice(TFLOG_MAGIC);
    } else if existing.len() < TFLOG_MAGIC.len() || &existing[..TFLOG_MAGIC.len()] != TFLOG_MAGIC {
        return Err(FormatError::BadMagic(0));
    }
    let json = serde_json::to_value(event).map_err(|e| FormatError::Serde(e.to_string()))?;
    let body = canonicalize(&json).map_err(|e| FormatError::Canonical(e.to_string()))?;
    let bytes = body.into_bytes();
    put_u32_be(existing, bytes.len())?;
    existing.extend_from_slice(&bytes);
    Ok(())
}

pub fn read_tflog(buf: &[u8]) -> Result<Vec<ProofEvent>, FormatError> {
    if buf.len() < TFLOG_MAGIC.len() {
        return Err(FormatError::Truncated(0));
    }
    if &buf[..TFLOG_MAGIC.len()] != TFLOG_MAGIC {
        return Err(FormatError::BadMagic(0));
    }
    let mut out = Vec::new();
    let mut off = TFLOG_MAGIC.len();
    while off < buf.len() {
        let len = read_u32_be(buf, off)? as usize;
        off += 4;
        if off + len > buf.len() {
            return Err(FormatError::BadLength(off - 4, len as u32));
        }
        let slice = &buf[off..off + len];
        let text = std::str::from_utf8(slice).map_err(|e| FormatError::Utf8(e.to_string()))?;
        let value: Value = serde_json::from_str(text).map_err(|e| FormatError::Serde(e.to_string()))?;
        let event: ProofEvent =
            serde_json::from_value(value).map_err(|e| FormatError::Serde(e.to_string()))?;
        out.push(event);
        off += len;
    }
    Ok(out)
}

// ---------- .tfproof ----------

pub fn write_tfproof(bundle: &ProofBundle, signature: &[u8]) -> Result<Vec<u8>, FormatError> {
    let mut buf = Vec::with_capacity(1024);
    buf.extend_from_slice(TFPROOF_MAGIC);
    let body_json = serde_json::to_value(bundle).map_err(|e| FormatError::Serde(e.to_string()))?;
    let body = canonicalize(&body_json).map_err(|e| FormatError::Canonical(e.to_string()))?;
    let body_bytes = body.into_bytes();
    put_u32_be(&mut buf, body_bytes.len())?;
    buf.extend_from_slice(&body_bytes);
    put_u32_be(&mut buf, signature.len())?;
    buf.extend_from_slice(signature);
    Ok(buf)
}

#[derive(Debug)]
pub struct TfproofParts {
    pub bundle: ProofBundle,
    pub signature: Vec<u8>,
    pub canonical_body: Vec<u8>,
}

pub fn read_tfproof(buf: &[u8]) -> Result<TfproofParts, FormatError> {
    if buf.len() < TFPROOF_MAGIC.len() {
        return Err(FormatError::Truncated(0));
    }
    if &buf[..TFPROOF_MAGIC.len()] != TFPROOF_MAGIC {
        return Err(FormatError::BadMagic(0));
    }
    let mut off = TFPROOF_MAGIC.len();
    let body_len = read_u32_be(buf, off)? as usize;
    off += 4;
    if off + body_len > buf.len() {
        return Err(FormatError::BadLength(off - 4, body_len as u32));
    }
    let body_slice = &buf[off..off + body_len];
    let body_text =
        std::str::from_utf8(body_slice).map_err(|e| FormatError::Utf8(e.to_string()))?;
    let body_value: Value =
        serde_json::from_str(body_text).map_err(|e| FormatError::Serde(e.to_string()))?;
    let bundle: ProofBundle =
        serde_json::from_value(body_value).map_err(|e| FormatError::Serde(e.to_string()))?;
    off += body_len;

    let sig_len = read_u32_be(buf, off)? as usize;
    off += 4;
    if off + sig_len > buf.len() {
        return Err(FormatError::BadLength(off - 4, sig_len as u32));
    }
    let signature = buf[off..off + sig_len].to_vec();

    Ok(TfproofParts {
        bundle,
        signature,
        canonical_body: body_slice.to_vec(),
    })
}
