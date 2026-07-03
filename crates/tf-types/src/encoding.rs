//! In-house RFC 4648 base64 codec (TrustForge owns its codec layer; see
//! `docs/dependency-audit.md`).
//!
//! Two engines cover every TrustForge use: [`STANDARD`] (padded, `+/`)
//! for signature payloads, vault material, and packet wire fields, and
//! [`URL_SAFE_NO_PAD`] (`-_`) for JOSE-style segments in the OAuth/GNAP/DID
//! bridges.
//!
//! Decoding is strict, matching the behavior of the `base64` crate defaults
//! this module replaced: no whitespace, no embedded padding, canonical
//! padding required for [`STANDARD`], padding forbidden for
//! [`URL_SAFE_NO_PAD`], and non-zero trailing bits rejected (a base64
//! string has exactly one valid decoding or none — no malleable sibling
//! encodings of signature material).

use core::fmt;

const STD_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Base64 decode failure. Carries enough context for diagnostics without
/// echoing the (possibly secret) input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// A byte outside the engine's alphabet (or misplaced `=`).
    InvalidByte { offset: usize, byte: u8 },
    /// Input length can never be produced by this engine's encoder.
    InvalidLength(usize),
    /// Padding missing, excessive, or forbidden for this engine.
    InvalidPadding,
    /// Bits left over in the final symbol are not zero; the encoding is
    /// non-canonical (would re-encode to a different string).
    InvalidTrailingBits,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::InvalidByte { offset, byte } => {
                write!(f, "invalid base64 byte 0x{byte:02x} at offset {offset}")
            }
            DecodeError::InvalidLength(len) => write!(f, "invalid base64 length {len}"),
            DecodeError::InvalidPadding => write!(f, "invalid base64 padding"),
            DecodeError::InvalidTrailingBits => write!(f, "non-canonical base64 trailing bits"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// A base64 engine: alphabet + padding policy. The two engines TrustForge
/// uses are exported as consts; the type is public so adapters can name it.
#[derive(Debug, Clone, Copy)]
pub struct Engine {
    alphabet: &'static [u8; 64],
    padded: bool,
}

/// RFC 4648 §4 standard alphabet, padded (`=`). Canonical padding is
/// required on decode.
pub const STANDARD: Engine = Engine {
    alphabet: STD_ALPHABET,
    padded: true,
};

/// RFC 4648 §5 URL-safe alphabet, unpadded. Padding bytes are rejected on
/// decode.
pub const URL_SAFE_NO_PAD: Engine = Engine {
    alphabet: URL_ALPHABET,
    padded: false,
};

impl Engine {
    pub fn encode(&self, input: impl AsRef<[u8]>) -> String {
        let input = input.as_ref();
        let mut out = Vec::with_capacity(input.len().div_ceil(3) * 4);
        let mut chunks = input.chunks_exact(3);
        for chunk in &mut chunks {
            let n = (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8) | u32::from(chunk[2]);
            out.push(self.alphabet[(n >> 18) as usize & 63]);
            out.push(self.alphabet[(n >> 12) as usize & 63]);
            out.push(self.alphabet[(n >> 6) as usize & 63]);
            out.push(self.alphabet[n as usize & 63]);
        }
        match chunks.remainder() {
            [] => {}
            [a] => {
                let n = u32::from(*a) << 16;
                out.push(self.alphabet[(n >> 18) as usize & 63]);
                out.push(self.alphabet[(n >> 12) as usize & 63]);
                if self.padded {
                    out.extend_from_slice(b"==");
                }
            }
            [a, b] => {
                let n = (u32::from(*a) << 16) | (u32::from(*b) << 8);
                out.push(self.alphabet[(n >> 18) as usize & 63]);
                out.push(self.alphabet[(n >> 12) as usize & 63]);
                out.push(self.alphabet[(n >> 6) as usize & 63]);
                if self.padded {
                    out.push(b'=');
                }
            }
            _ => unreachable!("chunks_exact(3) remainder is < 3"),
        }
        // Safety not needed: alphabet bytes and '=' are ASCII.
        String::from_utf8(out).expect("base64 output is ASCII")
    }

    pub fn decode(&self, input: impl AsRef<[u8]>) -> Result<Vec<u8>, DecodeError> {
        let mut input = input.as_ref();

        if self.padded {
            if input.len() % 4 != 0 {
                return Err(if input.len() % 4 == 1 && !input.contains(&b'=') {
                    DecodeError::InvalidLength(input.len())
                } else {
                    DecodeError::InvalidPadding
                });
            }
            if input.ends_with(b"==") {
                input = &input[..input.len() - 2];
            } else if input.ends_with(b"=") {
                input = &input[..input.len() - 1];
            }
        }

        // After canonical-padding removal (or for unpadded engines), the
        // symbol stream must have a remainder of 0, 2, or 3 — and no '='.
        match input.len() % 4 {
            1 => return Err(DecodeError::InvalidLength(input.len())),
            _ => {}
        }

        let sym = |offset: usize, byte: u8| -> Result<u32, DecodeError> {
            decode_symbol(self.alphabet, byte)
                .ok_or(DecodeError::InvalidByte { offset, byte })
                .map(u32::from)
        };

        let mut out = Vec::with_capacity(input.len() / 4 * 3 + 2);
        let mut chunks = input.chunks_exact(4);
        let mut offset = 0usize;
        for chunk in &mut chunks {
            let n = (sym(offset, chunk[0])? << 18)
                | (sym(offset + 1, chunk[1])? << 12)
                | (sym(offset + 2, chunk[2])? << 6)
                | sym(offset + 3, chunk[3])?;
            out.push((n >> 16) as u8);
            out.push((n >> 8) as u8);
            out.push(n as u8);
            offset += 4;
        }
        match chunks.remainder() {
            [] => {}
            [a, b] => {
                let n = (sym(offset, *a)? << 18) | (sym(offset + 1, *b)? << 12);
                if n & 0xFFFF != 0 {
                    return Err(DecodeError::InvalidTrailingBits);
                }
                out.push((n >> 16) as u8);
            }
            [a, b, c] => {
                let n = (sym(offset, *a)? << 18)
                    | (sym(offset + 1, *b)? << 12)
                    | (sym(offset + 2, *c)? << 6);
                if n & 0xFF != 0 {
                    return Err(DecodeError::InvalidTrailingBits);
                }
                out.push((n >> 16) as u8);
                out.push((n >> 8) as u8);
            }
            _ => unreachable!("chunks_exact(4) remainder is < 4"),
        }
        Ok(out)
    }
}

fn decode_symbol(alphabet: &[u8; 64], byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' if alphabet[62] == b'+' => Some(62),
        b'/' if alphabet[63] == b'/' => Some(63),
        b'-' if alphabet[62] == b'-' => Some(62),
        b'_' if alphabet[63] == b'_' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4648 §10 test vectors.
    const RFC_VECTORS: &[(&str, &str)] = &[
        ("", ""),
        ("f", "Zg=="),
        ("fo", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
    ];

    #[test]
    fn rfc4648_standard_vectors() {
        for (plain, encoded) in RFC_VECTORS {
            assert_eq!(STANDARD.encode(plain.as_bytes()), *encoded);
            assert_eq!(STANDARD.decode(encoded).unwrap(), plain.as_bytes());
        }
    }

    #[test]
    fn rfc4648_url_safe_vectors() {
        for (plain, encoded) in RFC_VECTORS {
            let unpadded = encoded.trim_end_matches('=');
            assert_eq!(URL_SAFE_NO_PAD.encode(plain.as_bytes()), unpadded);
            assert_eq!(URL_SAFE_NO_PAD.decode(unpadded).unwrap(), plain.as_bytes());
        }
    }

    #[test]
    fn url_safe_alphabet_round_trip() {
        // 0xfb 0xff exercises '-' and '_' (62/63) in the URL alphabet.
        let bytes = [0xfbu8, 0xff, 0xbf, 0xfe];
        let enc = URL_SAFE_NO_PAD.encode(bytes);
        assert!(enc.contains('-') || enc.contains('_'));
        assert_eq!(URL_SAFE_NO_PAD.decode(&enc).unwrap(), bytes);
        // Standard alphabet symbols are rejected by the URL engine and
        // vice versa.
        assert!(URL_SAFE_NO_PAD.decode("+/").is_err());
        assert!(STANDARD.decode("-_A=").is_err());
    }

    #[test]
    fn standard_requires_canonical_padding() {
        assert!(STANDARD.decode("Zg").is_err(), "missing padding");
        assert!(STANDARD.decode("Zg=").is_err(), "short padding");
        assert!(STANDARD.decode("Zm9v====").is_err(), "excess padding");
        assert!(STANDARD.decode("Z===").is_err(), "padding after 1 symbol");
        assert!(STANDARD.decode("Zg=A").is_err(), "embedded padding");
    }

    #[test]
    fn url_safe_rejects_padding() {
        assert!(URL_SAFE_NO_PAD.decode("Zg==").is_err());
        assert!(URL_SAFE_NO_PAD.decode("Zm8=").is_err());
    }

    #[test]
    fn rejects_whitespace_and_garbage() {
        assert!(STANDARD.decode("Zm 9v").is_err());
        assert!(STANDARD.decode("Zm9v\n").is_err());
        assert!(STANDARD.decode("Zm9v!AAA").is_err());
        assert!(URL_SAFE_NO_PAD.decode("Zg\r\n").is_err());
    }

    #[test]
    fn rejects_non_canonical_trailing_bits() {
        // "Zh" decodes the same byte as "Zg" only if trailing bits are
        // ignored; canonical decoding must refuse it.
        assert!(URL_SAFE_NO_PAD.decode("Zh").is_err());
        assert!(STANDARD.decode("Zh==").is_err());
        assert!(URL_SAFE_NO_PAD.decode("Zm9").is_err());
    }

    #[test]
    fn rejects_impossible_lengths() {
        assert!(URL_SAFE_NO_PAD.decode("Z").is_err());
        assert!(STANDARD.decode("Zm9vY").is_err());
    }

    #[test]
    fn binary_round_trip_all_lengths() {
        // Cover every remainder class with non-trivial bytes.
        let data: Vec<u8> = (0u16..=255).map(|b| b as u8).collect();
        for len in 0..data.len() {
            let slice = &data[..len];
            assert_eq!(STANDARD.decode(STANDARD.encode(slice)).unwrap(), slice);
            assert_eq!(
                URL_SAFE_NO_PAD
                    .decode(URL_SAFE_NO_PAD.encode(slice))
                    .unwrap(),
                slice
            );
        }
    }
}
