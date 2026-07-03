//! In-house CBOR codec (RFC 8949) — TrustForge owns its codec layer; see
//! `docs/dependency-audit.md`. Mirror of `tools/tf-types-ts/src/core/cbor.ts`.
//!
//! Scope: exactly what the TrustForge wire formats need.
//!
//! * **Encoding is deterministic**: smallest-width integer/length headers,
//!   definite lengths only, floats always emitted as 8-byte doubles.
//!   Map entries are emitted **in the order provided** — canonical key
//!   ordering is the caller's contract (`binary_format` sorts JSON keys
//!   lexicographically before building the tree; see the determinism
//!   notes there). This module must stay byte-parity with the TS encoder
//!   over `conformance/binary-format-vectors.yaml`.
//! * **Decoding is hardened** for externally produced CBOR (WebAuthn
//!   attestation objects, COSE keys): depth-limited, length headers are
//!   validated against remaining input before any allocation, and
//!   indefinite-length items are accepted (CTAP1-era encoders emit them)
//!   but bounded by the same limits. Trailing bytes after the first
//!   value are ignored, matching the previous decoder.

use std::fmt;

/// Maximum nesting depth accepted by the decoder. Deep enough for any
/// real packet or attestation; shallow enough that a hostile input
/// cannot blow the stack.
const MAX_DEPTH: usize = 128;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// Whole CBOR integer range: unsigned 0..=u64::MAX and negative
    /// -1..=-(u64::MAX+1) both fit in i128.
    Integer(i128),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    /// Entries keep insertion order; the encoder does not sort.
    Map(Vec<(Value, Value)>),
    Tag(u64, Box<Value>),
    Bool(bool),
    Null,
    /// Also used for CBOR `undefined` (0xf7) on decode.
    Float(f64),
}

impl Value {
    /// Convenience: look up a text key in a map.
    pub fn map_get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Map(entries) => entries.iter().find_map(|(k, v)| match k {
                Value::Text(t) if t == key => Some(v),
                _ => None,
            }),
            _ => None,
        }
    }

    /// Convenience: look up an integer key in a map (COSE-style).
    pub fn map_get_int(&self, key: i128) -> Option<&Value> {
        match self {
            Value::Map(entries) => entries.iter().find_map(|(k, v)| match k {
                Value::Integer(i) if *i == key => Some(v),
                _ => None,
            }),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(t) => Some(t),
            _ => None,
        }
    }

    pub fn as_integer(&self) -> Option<i128> {
        match self {
            Value::Integer(i) => Some(*i),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CborError {
    /// Input ended before the value did.
    Truncated,
    /// Structurally invalid or unsupported input byte.
    Invalid(&'static str),
    /// Nesting exceeded [`MAX_DEPTH`].
    TooDeep,
    /// A value cannot be represented (encode side).
    Unrepresentable(&'static str),
}

impl fmt::Display for CborError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CborError::Truncated => write!(f, "truncated CBOR input"),
            CborError::Invalid(what) => write!(f, "invalid CBOR: {what}"),
            CborError::TooDeep => write!(f, "CBOR nesting exceeds depth limit"),
            CborError::Unrepresentable(what) => write!(f, "unrepresentable in CBOR: {what}"),
        }
    }
}

impl std::error::Error for CborError {}

/* ------------------------------------------------------------------ */
/*  Encoding                                                           */
/* ------------------------------------------------------------------ */

fn put_header(out: &mut Vec<u8>, major: u8, arg: u64) {
    let mt = major << 5;
    if arg < 24 {
        out.push(mt | arg as u8);
    } else if arg <= u8::MAX as u64 {
        out.push(mt | 24);
        out.push(arg as u8);
    } else if arg <= u16::MAX as u64 {
        out.push(mt | 25);
        out.extend_from_slice(&(arg as u16).to_be_bytes());
    } else if arg <= u32::MAX as u64 {
        out.push(mt | 26);
        out.extend_from_slice(&(arg as u32).to_be_bytes());
    } else {
        out.push(mt | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

fn encode_into(value: &Value, out: &mut Vec<u8>) -> Result<(), CborError> {
    match value {
        Value::Integer(i) => {
            if *i >= 0 {
                let u = u64::try_from(*i)
                    .map_err(|_| CborError::Unrepresentable("integer above u64::MAX"))?;
                put_header(out, 0, u);
            } else {
                let magnitude = i
                    .checked_neg()
                    .and_then(|m| m.checked_sub(1))
                    .and_then(|m| u64::try_from(m).ok())
                    .ok_or(CborError::Unrepresentable("integer below -2^64"))?;
                put_header(out, 1, magnitude);
            }
        }
        Value::Bytes(b) => {
            put_header(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Value::Text(t) => {
            put_header(out, 3, t.len() as u64);
            out.extend_from_slice(t.as_bytes());
        }
        Value::Array(items) => {
            put_header(out, 4, items.len() as u64);
            for item in items {
                encode_into(item, out)?;
            }
        }
        Value::Map(entries) => {
            put_header(out, 5, entries.len() as u64);
            for (k, v) in entries {
                encode_into(k, out)?;
                encode_into(v, out)?;
            }
        }
        Value::Tag(tag, inner) => {
            put_header(out, 6, *tag);
            encode_into(inner, out)?;
        }
        Value::Bool(b) => out.push(if *b { 0xf5 } else { 0xf4 }),
        Value::Null => out.push(0xf6),
        Value::Float(f) => {
            // Always 8-byte doubles: parity with the TS encoder
            // (cbor-x `useFloat32: 0`).
            out.push(0xfb);
            out.extend_from_slice(&f.to_be_bytes());
        }
    }
    Ok(())
}

pub fn encode(value: &Value) -> Result<Vec<u8>, CborError> {
    let mut out = Vec::new();
    encode_into(value, &mut out)?;
    Ok(out)
}

/* ------------------------------------------------------------------ */
/*  Decoding                                                           */
/* ------------------------------------------------------------------ */

struct Decoder<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    fn byte(&mut self) -> Result<u8, CborError> {
        let b = *self.buf.get(self.pos).ok_or(CborError::Truncated)?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CborError> {
        // `n` was validated against remaining input by `arg_as_len`, but
        // guard again so this helper is safe standalone.
        let end = self.pos.checked_add(n).ok_or(CborError::Truncated)?;
        if end > self.buf.len() {
            return Err(CborError::Truncated);
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn arg(&mut self, info: u8) -> Result<u64, CborError> {
        match info {
            0..=23 => Ok(info as u64),
            24 => Ok(self.byte()? as u64),
            25 => Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()) as u64),
            26 => Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()) as u64),
            27 => Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap())),
            _ => Err(CborError::Invalid("reserved additional-info value")),
        }
    }

    /// Interpret a header argument as a byte/item length, rejecting
    /// anything that cannot possibly fit in the remaining input — this
    /// is the allocation guard for hostile length headers.
    fn arg_as_len(&self, arg: u64) -> Result<usize, CborError> {
        let remaining = self.buf.len() - self.pos;
        if arg > remaining as u64 {
            return Err(CborError::Truncated);
        }
        Ok(arg as usize)
    }

    fn value(&mut self, depth: usize) -> Result<Value, CborError> {
        if depth > MAX_DEPTH {
            return Err(CborError::TooDeep);
        }
        let initial = self.byte()?;
        let major = initial >> 5;
        let info = initial & 0x1f;
        match major {
            0 => Ok(Value::Integer(self.arg(info)? as i128)),
            1 => Ok(Value::Integer(-1 - self.arg(info)? as i128)),
            2 => {
                if info == 31 {
                    self.indefinite_string(depth, 2).map(Value::Bytes)
                } else {
                    let arg = self.arg(info)?;
                    let len = self.arg_as_len(arg)?;
                    Ok(Value::Bytes(self.take(len)?.to_vec()))
                }
            }
            3 => {
                let bytes = if info == 31 {
                    self.indefinite_string(depth, 3)?
                } else {
                    let arg = self.arg(info)?;
                    let len = self.arg_as_len(arg)?;
                    self.take(len)?.to_vec()
                };
                String::from_utf8(bytes)
                    .map(Value::Text)
                    .map_err(|_| CborError::Invalid("text string is not UTF-8"))
            }
            4 => {
                if info == 31 {
                    let mut items = Vec::new();
                    while !self.at_break()? {
                        items.push(self.value(depth + 1)?);
                    }
                    Ok(Value::Array(items))
                } else {
                    // Each item is at least one byte, so the count is
                    // bounded by the remaining input.
                    let arg = self.arg(info)?;
                    let len = self.arg_as_len(arg)?;
                    let mut items = Vec::with_capacity(len);
                    for _ in 0..len {
                        items.push(self.value(depth + 1)?);
                    }
                    Ok(Value::Array(items))
                }
            }
            5 => {
                if info == 31 {
                    let mut entries = Vec::new();
                    while !self.at_break()? {
                        let k = self.value(depth + 1)?;
                        let v = self.value(depth + 1)?;
                        entries.push((k, v));
                    }
                    Ok(Value::Map(entries))
                } else {
                    let count = self.arg(info)?;
                    // Each entry is at least two bytes.
                    if count > (self.buf.len() - self.pos) as u64 / 2 {
                        return Err(CborError::Truncated);
                    }
                    let count = count as usize;
                    let mut entries = Vec::with_capacity(count);
                    for _ in 0..count {
                        let k = self.value(depth + 1)?;
                        let v = self.value(depth + 1)?;
                        entries.push((k, v));
                    }
                    Ok(Value::Map(entries))
                }
            }
            6 => {
                let tag = self.arg(info)?;
                Ok(Value::Tag(tag, Box::new(self.value(depth + 1)?)))
            }
            7 => match info {
                20 => Ok(Value::Bool(false)),
                21 => Ok(Value::Bool(true)),
                22 => Ok(Value::Null),
                23 => Ok(Value::Null), // undefined → null
                24 => {
                    let b = self.byte()?;
                    if b < 32 {
                        return Err(CborError::Invalid("non-minimal simple value"));
                    }
                    Ok(Value::Integer(b as i128)) // unassigned simple value
                }
                25 => {
                    let raw = u16::from_be_bytes(self.take(2)?.try_into().unwrap());
                    Ok(Value::Float(half_to_f64(raw)))
                }
                26 => {
                    let raw = u32::from_be_bytes(self.take(4)?.try_into().unwrap());
                    Ok(Value::Float(f32::from_bits(raw) as f64))
                }
                27 => {
                    let raw = u64::from_be_bytes(self.take(8)?.try_into().unwrap());
                    Ok(Value::Float(f64::from_bits(raw)))
                }
                31 => Err(CborError::Invalid("unexpected break")),
                _ => Err(CborError::Invalid("reserved simple value")),
            },
            _ => unreachable!("major type is 3 bits"),
        }
    }

    /// Indefinite-length byte/text string: a sequence of definite chunks
    /// of the same major type terminated by 0xff.
    fn indefinite_string(&mut self, depth: usize, major: u8) -> Result<Vec<u8>, CborError> {
        if depth + 1 > MAX_DEPTH {
            return Err(CborError::TooDeep);
        }
        let mut out = Vec::new();
        loop {
            let initial = self.byte()?;
            if initial == 0xff {
                return Ok(out);
            }
            if initial >> 5 != major || initial & 0x1f == 31 {
                return Err(CborError::Invalid("bad chunk in indefinite string"));
            }
            let arg = self.arg(initial & 0x1f)?;
            let len = self.arg_as_len(arg)?;
            out.extend_from_slice(self.take(len)?);
        }
    }

    fn at_break(&mut self) -> Result<bool, CborError> {
        if *self.buf.get(self.pos).ok_or(CborError::Truncated)? == 0xff {
            self.pos += 1;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

fn half_to_f64(raw: u16) -> f64 {
    // RFC 8949 appendix D reference algorithm.
    let exp = (raw >> 10) & 0x1f;
    let mant = (raw & 0x3ff) as f64;
    let magnitude = match exp {
        0 => mant * 2f64.powi(-24),
        31 => {
            if mant == 0.0 {
                f64::INFINITY
            } else {
                f64::NAN
            }
        }
        _ => (mant + 1024.0) * 2f64.powi(exp as i32 - 25),
    };
    if raw & 0x8000 != 0 {
        -magnitude
    } else {
        magnitude
    }
}

/// Decode the first CBOR value in `bytes`. Trailing bytes are ignored,
/// matching the replaced decoder's behavior.
pub fn decode(bytes: &[u8]) -> Result<Value, CborError> {
    let mut d = Decoder { buf: bytes, pos: 0 };
    d.value(0)
}

/* ------------------------------------------------------------------ */
/*  serde_json::Value bridging                                         */
/* ------------------------------------------------------------------ */

/// Build a CBOR value from a JSON value. Object key order is preserved
/// as-is — sort beforehand for canonical output.
pub fn from_json(v: &serde_json::Value) -> Result<Value, CborError> {
    use serde_json::Value as J;
    Ok(match v {
        J::Null => Value::Null,
        J::Bool(b) => Value::Bool(*b),
        J::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Integer(i as i128)
            } else if let Some(u) = n.as_u64() {
                Value::Integer(u as i128)
            } else {
                Value::Float(n.as_f64().ok_or(CborError::Unrepresentable("number"))?)
            }
        }
        J::String(s) => Value::Text(s.clone()),
        J::Array(items) => Value::Array(
            items
                .iter()
                .map(from_json)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        J::Object(map) => Value::Map(
            map.iter()
                .map(|(k, val)| Ok((Value::Text(k.clone()), from_json(val)?)))
                .collect::<Result<Vec<_>, CborError>>()?,
        ),
    })
}

/// Convert a decoded CBOR value back to JSON. Fails on shapes JSON
/// cannot express (byte strings, non-text map keys, tags) — the typed
/// wire bodies never contain them.
pub fn to_json(v: &Value) -> Result<serde_json::Value, CborError> {
    use serde_json::Value as J;
    Ok(match v {
        Value::Null => J::Null,
        Value::Bool(b) => J::Bool(*b),
        Value::Integer(i) => {
            if let Ok(n) = i64::try_from(*i) {
                J::Number(n.into())
            } else if let Ok(n) = u64::try_from(*i) {
                J::Number(n.into())
            } else {
                return Err(CborError::Unrepresentable("integer outside JSON range"));
            }
        }
        Value::Float(f) => serde_json::Number::from_f64(*f)
            .map(J::Number)
            .ok_or(CborError::Unrepresentable("non-finite float"))?,
        Value::Text(t) => J::String(t.clone()),
        Value::Array(items) => J::Array(
            items
                .iter()
                .map(to_json)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        Value::Map(entries) => {
            let mut out = serde_json::Map::with_capacity(entries.len());
            for (k, val) in entries {
                let Value::Text(key) = k else {
                    return Err(CborError::Unrepresentable("non-text map key in JSON"));
                };
                out.insert(key.clone(), to_json(val)?);
            }
            J::Object(out)
        }
        Value::Tag(..) => return Err(CborError::Unrepresentable("tag in JSON")),
        Value::Bytes(_) => return Err(CborError::Unrepresentable("byte string in JSON")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn rfc8949_appendix_a_encodings() {
        // (value, expected hex) pairs from RFC 8949 appendix A.
        let cases: Vec<(Value, &str)> = vec![
            (Value::Integer(0), "00"),
            (Value::Integer(10), "0a"),
            (Value::Integer(23), "17"),
            (Value::Integer(24), "1818"),
            (Value::Integer(100), "1864"),
            (Value::Integer(1000), "1903e8"),
            (Value::Integer(1000000), "1a000f4240"),
            (Value::Integer(1000000000000), "1b000000e8d4a51000"),
            (Value::Integer(u64::MAX as i128), "1bffffffffffffffff"),
            (Value::Integer(-1), "20"),
            (Value::Integer(-10), "29"),
            (Value::Integer(-100), "3863"),
            (Value::Integer(-1000), "3903e7"),
            (Value::Integer(-(u64::MAX as i128) - 1), "3bffffffffffffffff"),
            (Value::Bool(false), "f4"),
            (Value::Bool(true), "f5"),
            (Value::Null, "f6"),
            (Value::Float(1.1), "fb3ff199999999999a"),
            (Value::Float(-4.1), "fbc010666666666666"),
            (Value::Bytes(vec![]), "40"),
            (Value::Bytes(vec![1, 2, 3, 4]), "4401020304"),
            (Value::Text(String::new()), "60"),
            (Value::Text("IETF".into()), "6449455446"),
            (Value::Text("\u{00fc}".into()), "62c3bc"),
            (Value::Text("\u{6c34}".into()), "63e6b0b4"),
            (Value::Array(vec![]), "80"),
            (
                Value::Array(vec![
                    Value::Integer(1),
                    Value::Integer(2),
                    Value::Integer(3),
                ]),
                "83010203",
            ),
            (Value::Map(vec![]), "a0"),
            (
                Value::Map(vec![
                    (Value::Text("a".into()), Value::Integer(1)),
                    (
                        Value::Text("b".into()),
                        Value::Array(vec![Value::Integer(2), Value::Integer(3)]),
                    ),
                ]),
                "a26161016162820203",
            ),
            (
                Value::Tag(1, Box::new(Value::Integer(1363896240))),
                "c11a514b67b0",
            ),
        ];
        for (value, expected) in cases {
            assert_eq!(hex(&encode(&value).unwrap()), expected, "{value:?}");
            assert_eq!(decode(&unhex(expected)).unwrap(), value, "{expected}");
        }
    }

    #[test]
    fn float_widths_decode_to_f64() {
        assert_eq!(decode(&unhex("f90000")).unwrap(), Value::Float(0.0));
        assert_eq!(decode(&unhex("f93c00")).unwrap(), Value::Float(1.0));
        assert_eq!(decode(&unhex("f97c00")).unwrap(), Value::Float(f64::INFINITY));
        assert_eq!(decode(&unhex("fa47c35000")).unwrap(), Value::Float(100000.0));
        // Half-precision subnormal.
        assert_eq!(
            decode(&unhex("f90001")).unwrap(),
            Value::Float(5.960464477539063e-8)
        );
    }

    #[test]
    fn indefinite_lengths_accepted() {
        // (_ h'0102', h'030405') from RFC 8949.
        assert_eq!(
            decode(&unhex("5f42010243030405ff")).unwrap(),
            Value::Bytes(vec![1, 2, 3, 4, 5])
        );
        // ["a", {_ "b": "c"}]
        assert_eq!(
            decode(&unhex("826161bf61626163ff")).unwrap(),
            Value::Array(vec![
                Value::Text("a".into()),
                Value::Map(vec![(Value::Text("b".into()), Value::Text("c".into()))]),
            ])
        );
    }

    #[test]
    fn hostile_inputs_rejected_without_allocation() {
        // Claims a 4 GiB byte string with 3 bytes of input.
        assert_eq!(
            decode(&unhex("5affffffff")).unwrap_err(),
            CborError::Truncated
        );
        // Claims 2^64-1 array items.
        assert_eq!(
            decode(&unhex("9bffffffffffffffff")).unwrap_err(),
            CborError::Truncated
        );
        // Map with absurd entry count.
        assert_eq!(
            decode(&unhex("bbffffffffffffffff")).unwrap_err(),
            CborError::Truncated
        );
        // Empty input.
        assert_eq!(decode(&[]).unwrap_err(), CborError::Truncated);
        // Bare break byte.
        assert!(matches!(
            decode(&unhex("ff")).unwrap_err(),
            CborError::Invalid(_)
        ));
        // Invalid UTF-8 text.
        assert!(matches!(
            decode(&unhex("61ff")).unwrap_err(),
            CborError::Invalid(_)
        ));
    }

    #[test]
    fn depth_limit_enforced() {
        // 200 nested single-item arrays.
        let mut buf = vec![0x81u8; 200];
        buf.push(0x00);
        assert_eq!(decode(&buf).unwrap_err(), CborError::TooDeep);
        // 100 nested arrays is fine.
        let mut ok = vec![0x81u8; 100];
        ok.push(0x00);
        assert!(decode(&ok).is_ok());
    }

    #[test]
    fn trailing_bytes_ignored() {
        assert_eq!(decode(&unhex("01ffffff")).unwrap(), Value::Integer(1));
    }

    #[test]
    fn json_round_trip() {
        let json = serde_json::json!({
            "z": "last",
            "a": [1, 2.5, true, null, {"nested": "x"}],
            "n": -42,
            "big": u64::MAX,
        });
        let value = from_json(&json).unwrap();
        let bytes = encode(&value).unwrap();
        let back = to_json(&decode(&bytes).unwrap()).unwrap();
        assert_eq!(back, json);
    }
}
