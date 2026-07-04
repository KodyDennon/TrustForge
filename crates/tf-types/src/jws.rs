//! In-house JWS/JWT compact-serialization verify + sign (RFC 7515/7519)
//! — TrustForge owns its envelope layer; see `docs/dependency-audit.md`.
//! Mirror of `tools/tf-types-ts/src/core/jws.ts`.
//!
//! **No custom cryptography**: every signature operation delegates to a
//! reviewed primitive crate — `ed25519-dalek` (EdDSA), `p256`/`p384`
//! (ES256/ES384), `rsa` (RS256/RS384/RS512). This module only owns the
//! *envelope*: compact-form parsing, base64url handling, the algorithm
//! allow-list, and registered-claim validation.
//!
//! Security posture (deliberate, do not relax):
//! - `alg` is never trusted from the token alone — verification requires
//!   the caller's explicit allow-list, and `none` is unrepresentable.
//! - Key type and algorithm must agree (an RSA key never verifies an
//!   ES256 token, killing key-confusion downgrades).
//! - `exp` is validated by default; `iss`/`aud` are validated whenever
//!   the caller configures them, and configured-but-missing claims fail.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::encoding::URL_SAFE_NO_PAD;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwsError {
    Malformed(String),
    UnsupportedAlgorithm(String),
    AlgorithmNotAllowed(String),
    BadKey(String),
    BadSignature,
    InvalidClaim(String),
}

impl std::fmt::Display for JwsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JwsError::Malformed(m) => write!(f, "malformed JWT: {m}"),
            JwsError::UnsupportedAlgorithm(a) => write!(f, "unsupported algorithm: {a}"),
            JwsError::AlgorithmNotAllowed(a) => write!(f, "algorithm {a} not allowed"),
            JwsError::BadKey(m) => write!(f, "bad key: {m}"),
            JwsError::BadSignature => write!(f, "signature verification failed"),
            JwsError::InvalidClaim(m) => write!(f, "invalid claim: {m}"),
        }
    }
}

impl std::error::Error for JwsError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    ES256,
    ES384,
    RS256,
    RS384,
    RS512,
    EdDSA,
}

impl Algorithm {
    pub fn parse(name: &str) -> Result<Self, JwsError> {
        match name.to_ascii_uppercase().as_str() {
            "ES256" => Ok(Algorithm::ES256),
            "ES384" => Ok(Algorithm::ES384),
            "RS256" => Ok(Algorithm::RS256),
            "RS384" => Ok(Algorithm::RS384),
            "RS512" => Ok(Algorithm::RS512),
            "EDDSA" => Ok(Algorithm::EdDSA),
            other => Err(JwsError::UnsupportedAlgorithm(other.to_string())),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Algorithm::ES256 => "ES256",
            Algorithm::ES384 => "ES384",
            Algorithm::RS256 => "RS256",
            Algorithm::RS384 => "RS384",
            Algorithm::RS512 => "RS512",
            Algorithm::EdDSA => "EdDSA",
        }
    }
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    pub alg: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub typ: Option<String>,
    /// DPoP-style embedded public key.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub jwk: Option<Value>,
}

impl Header {
    pub fn new(alg: Algorithm) -> Self {
        Header {
            alg: alg.name().to_string(),
            kid: None,
            typ: Some("JWT".to_string()),
            jwk: None,
        }
    }

    pub fn algorithm(&self) -> Result<Algorithm, JwsError> {
        Algorithm::parse(&self.alg)
    }
}

/// Parse the (unverified!) header segment. Never make a trust decision
/// from this alone.
pub fn decode_header(token: &str) -> Result<Header, JwsError> {
    let first = token
        .split('.')
        .next()
        .ok_or_else(|| JwsError::Malformed("empty token".into()))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(first)
        .map_err(|e| JwsError::Malformed(format!("header base64url: {e}")))?;
    serde_json::from_slice(&bytes).map_err(|e| JwsError::Malformed(format!("header JSON: {e}")))
}

/* ------------------------------------------------------------------ */
/*  Keys                                                               */
/* ------------------------------------------------------------------ */

pub enum DecodingKey {
    Ed25519(ed25519_dalek::VerifyingKey),
    P256(p256::ecdsa::VerifyingKey),
    P384(p384::ecdsa::VerifyingKey),
    Rsa(rsa::RsaPublicKey),
}

impl DecodingKey {
    /// From JWK EC members (base64url x/y). Curve is inferred from the
    /// coordinate width.
    pub fn from_ec_components(x: &str, y: &str) -> Result<Self, JwsError> {
        let xb = b64u(x, "x")?;
        let yb = b64u(y, "y")?;
        if xb.len() != yb.len() {
            return Err(JwsError::BadKey("EC x/y length mismatch".into()));
        }
        let mut sec1 = Vec::with_capacity(1 + xb.len() + yb.len());
        sec1.push(0x04);
        sec1.extend_from_slice(&xb);
        sec1.extend_from_slice(&yb);
        match xb.len() {
            32 => p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
                .map(DecodingKey::P256)
                .map_err(|e| JwsError::BadKey(format!("P-256 point: {e}"))),
            48 => p384::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
                .map(DecodingKey::P384)
                .map_err(|e| JwsError::BadKey(format!("P-384 point: {e}"))),
            n => Err(JwsError::BadKey(format!("unsupported EC width {n}"))),
        }
    }

    /// From JWK RSA members (base64url n/e).
    pub fn from_rsa_components(n: &str, e: &str) -> Result<Self, JwsError> {
        let nb = b64u(n, "n")?;
        let eb = b64u(e, "e")?;
        let key = rsa::RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(&nb),
            rsa::BigUint::from_bytes_be(&eb),
        )
        .map_err(|e| JwsError::BadKey(format!("RSA components: {e}")))?;
        Ok(DecodingKey::Rsa(key))
    }

    /// From JWK OKP member (base64url x, Ed25519).
    pub fn from_ed_components(x: &str) -> Result<Self, JwsError> {
        let xb = b64u(x, "x")?;
        let arr: [u8; 32] = xb
            .as_slice()
            .try_into()
            .map_err(|_| JwsError::BadKey("Ed25519 x must be 32 bytes".into()))?;
        ed25519_dalek::VerifyingKey::from_bytes(&arr)
            .map(DecodingKey::Ed25519)
            .map_err(|e| JwsError::BadKey(format!("Ed25519 point: {e}")))
    }

    fn verify(&self, alg: Algorithm, message: &[u8], signature: &[u8]) -> Result<(), JwsError> {
        match (self, alg) {
            (DecodingKey::Ed25519(key), Algorithm::EdDSA) => {
                use ed25519_dalek::Verifier;
                let sig = ed25519_dalek::Signature::from_slice(signature)
                    .map_err(|_| JwsError::BadSignature)?;
                key.verify(message, &sig).map_err(|_| JwsError::BadSignature)
            }
            (DecodingKey::P256(key), Algorithm::ES256) => {
                use p256::ecdsa::signature::Verifier;
                let sig = p256::ecdsa::Signature::from_slice(signature)
                    .map_err(|_| JwsError::BadSignature)?;
                key.verify(message, &sig).map_err(|_| JwsError::BadSignature)
            }
            (DecodingKey::P384(key), Algorithm::ES384) => {
                use p384::ecdsa::signature::Verifier;
                let sig = p384::ecdsa::Signature::from_slice(signature)
                    .map_err(|_| JwsError::BadSignature)?;
                key.verify(message, &sig).map_err(|_| JwsError::BadSignature)
            }
            (DecodingKey::Rsa(key), Algorithm::RS256) => {
                verify_rsa::<sha2::Sha256>(key, message, signature)
            }
            (DecodingKey::Rsa(key), Algorithm::RS384) => {
                verify_rsa::<sha2::Sha384>(key, message, signature)
            }
            (DecodingKey::Rsa(key), Algorithm::RS512) => {
                verify_rsa::<sha2::Sha512>(key, message, signature)
            }
            // Key type and algorithm must agree — no cross-verification.
            _ => Err(JwsError::AlgorithmNotAllowed(format!(
                "{} incompatible with the provided key type",
                alg
            ))),
        }
    }
}

fn verify_rsa<D>(key: &rsa::RsaPublicKey, message: &[u8], signature: &[u8]) -> Result<(), JwsError>
where
    D: rsa::sha2::Digest + rsa::pkcs8::AssociatedOid,
{
    use rsa::signature::Verifier;
    let verifying = rsa::pkcs1v15::VerifyingKey::<D>::new(key.clone());
    let sig = rsa::pkcs1v15::Signature::try_from(signature).map_err(|_| JwsError::BadSignature)?;
    verifying
        .verify(message, &sig)
        .map_err(|_| JwsError::BadSignature)
}

fn b64u(s: &str, what: &str) -> Result<Vec<u8>, JwsError> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| JwsError::BadKey(format!("base64url {what}: {e}")))
}

/* ------------------------------------------------------------------ */
/*  Validation                                                         */
/* ------------------------------------------------------------------ */

#[derive(Debug, Clone)]
pub struct Validation {
    pub algorithms: Vec<Algorithm>,
    /// Clock tolerance in seconds, applied to `exp` and `nbf`.
    pub leeway: u64,
    pub validate_exp: bool,
    pub validate_nbf: bool,
    issuer: Option<Vec<String>>,
    audience: Option<Vec<String>>,
}

impl Validation {
    pub fn new(alg: Algorithm) -> Self {
        Validation {
            algorithms: vec![alg],
            leeway: 0,
            validate_exp: true,
            validate_nbf: false,
            issuer: None,
            audience: None,
        }
    }

    pub fn set_issuer<T: ToString>(&mut self, issuers: &[T]) {
        self.issuer = Some(issuers.iter().map(|i| i.to_string()).collect());
    }

    pub fn set_audience<T: ToString>(&mut self, audiences: &[T]) {
        self.audience = Some(audiences.iter().map(|a| a.to_string()).collect());
    }
}

#[derive(Debug)]
pub struct TokenData<T> {
    pub header: Header,
    pub claims: T,
}

/// Verify a compact JWS and deserialize its payload, enforcing the
/// registered claims configured on `validation`.
pub fn decode<T: DeserializeOwned>(
    token: &str,
    key: &DecodingKey,
    validation: &Validation,
) -> Result<TokenData<T>, JwsError> {
    let mut parts = token.split('.');
    let (h, p, s) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s), None) => (h, p, s),
        _ => return Err(JwsError::Malformed("expected three dot-separated segments".into())),
    };
    let header: Header = {
        let bytes = URL_SAFE_NO_PAD
            .decode(h)
            .map_err(|e| JwsError::Malformed(format!("header base64url: {e}")))?;
        serde_json::from_slice(&bytes).map_err(|e| JwsError::Malformed(format!("header JSON: {e}")))?
    };
    let alg = header.algorithm()?;
    if !validation.algorithms.contains(&alg) {
        return Err(JwsError::AlgorithmNotAllowed(alg.name().to_string()));
    }
    let signature = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| JwsError::Malformed(format!("signature base64url: {e}")))?;
    let message_len = h.len() + 1 + p.len();
    let message = &token.as_bytes()[..message_len];
    key.verify(alg, message, &signature)?;

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(p)
        .map_err(|e| JwsError::Malformed(format!("payload base64url: {e}")))?;
    let claims_value: Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| JwsError::Malformed(format!("payload JSON: {e}")))?;
    validate_registered_claims(&claims_value, validation)?;
    let claims = serde_json::from_value(claims_value)
        .map_err(|e| JwsError::Malformed(format!("claims shape: {e}")))?;
    Ok(TokenData { header, claims })
}

fn validate_registered_claims(claims: &Value, v: &Validation) -> Result<(), JwsError> {
    let now = now_unix();
    if v.validate_exp {
        let exp = claims
            .get("exp")
            .and_then(Value::as_u64)
            .ok_or_else(|| JwsError::InvalidClaim("exp missing".into()))?;
        if exp.saturating_add(v.leeway) < now {
            return Err(JwsError::InvalidClaim("token expired".into()));
        }
    }
    if v.validate_nbf {
        if let Some(nbf) = claims.get("nbf").and_then(Value::as_u64) {
            if nbf.saturating_sub(v.leeway) > now {
                return Err(JwsError::InvalidClaim("token not yet valid".into()));
            }
        }
    }
    if let Some(issuers) = &v.issuer {
        let iss = claims
            .get("iss")
            .and_then(Value::as_str)
            .ok_or_else(|| JwsError::InvalidClaim("iss missing".into()))?;
        if !issuers.iter().any(|i| i == iss) {
            return Err(JwsError::InvalidClaim(format!("issuer {iss} not accepted")));
        }
    }
    if let Some(audiences) = &v.audience {
        let ok = match claims.get("aud") {
            Some(Value::String(a)) => audiences.iter().any(|x| x == a),
            Some(Value::Array(arr)) => arr
                .iter()
                .filter_map(Value::as_str)
                .any(|a| audiences.iter().any(|x| x == a)),
            _ => false,
        };
        if !ok {
            return Err(JwsError::InvalidClaim("audience not accepted".into()));
        }
    }
    Ok(())
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/* ------------------------------------------------------------------ */
/*  Signing (tests and vector generation)                              */
/* ------------------------------------------------------------------ */

pub enum EncodingKey {
    Ed25519(Box<ed25519_dalek::SigningKey>),
    P256(Box<p256::ecdsa::SigningKey>),
}

impl EncodingKey {
    pub fn from_ed_pem(pem: &[u8]) -> Result<Self, JwsError> {
        use ed25519_dalek::pkcs8::DecodePrivateKey;
        let text =
            std::str::from_utf8(pem).map_err(|_| JwsError::BadKey("PEM not UTF-8".into()))?;
        ed25519_dalek::SigningKey::from_pkcs8_pem(text)
            .map(|k| EncodingKey::Ed25519(Box::new(k)))
            .map_err(|e| JwsError::BadKey(format!("Ed25519 PKCS#8: {e}")))
    }

    pub fn from_ec_pem(pem: &[u8]) -> Result<Self, JwsError> {
        use p256::pkcs8::DecodePrivateKey;
        let text =
            std::str::from_utf8(pem).map_err(|_| JwsError::BadKey("PEM not UTF-8".into()))?;
        p256::SecretKey::from_pkcs8_pem(text)
            .map(|k| EncodingKey::P256(Box::new(p256::ecdsa::SigningKey::from(k))))
            .map_err(|e| JwsError::BadKey(format!("EC PKCS#8: {e}")))
    }

    fn sign(&self, alg: Algorithm, message: &[u8]) -> Result<Vec<u8>, JwsError> {
        match (self, alg) {
            (EncodingKey::Ed25519(key), Algorithm::EdDSA) => {
                use ed25519_dalek::Signer;
                Ok(key.sign(message).to_bytes().to_vec())
            }
            (EncodingKey::P256(key), Algorithm::ES256) => {
                use p256::ecdsa::signature::Signer;
                let sig: p256::ecdsa::Signature = key.sign(message);
                Ok(sig.to_bytes().to_vec())
            }
            _ => Err(JwsError::AlgorithmNotAllowed(format!(
                "{} incompatible with the provided signing key",
                alg
            ))),
        }
    }
}

/// Mint a compact JWS.
pub fn encode<T: Serialize>(
    header: &Header,
    claims: &T,
    key: &EncodingKey,
) -> Result<String, JwsError> {
    let alg = header.algorithm()?;
    let header_json =
        serde_json::to_vec(header).map_err(|e| JwsError::Malformed(e.to_string()))?;
    let payload_json =
        serde_json::to_vec(claims).map_err(|e| JwsError::Malformed(e.to_string()))?;
    let mut token = String::new();
    token.push_str(&URL_SAFE_NO_PAD.encode(header_json));
    token.push('.');
    token.push_str(&URL_SAFE_NO_PAD.encode(payload_json));
    let signature = key.sign(alg, token.as_bytes())?;
    token.push('.');
    token.push_str(&URL_SAFE_NO_PAD.encode(signature));
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ed_pair() -> (EncodingKey, DecodingKey) {
        let signing = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let x = URL_SAFE_NO_PAD.encode(signing.verifying_key().as_bytes());
        (
            EncodingKey::Ed25519(Box::new(signing)),
            DecodingKey::from_ed_components(&x).unwrap(),
        )
    }

    fn claims(exp_offset: i64) -> Value {
        json!({
            "iss": "https://idp.example.com",
            "sub": "alice",
            "aud": "tf://example.com",
            "exp": (now_unix() as i64 + exp_offset) as u64,
        })
    }

    fn validation() -> Validation {
        let mut v = Validation::new(Algorithm::EdDSA);
        v.set_issuer(&["https://idp.example.com"]);
        v.set_audience(&["tf://example.com"]);
        v
    }

    #[test]
    fn round_trip_eddsa() {
        let (enc, dec) = ed_pair();
        let token = encode(&Header::new(Algorithm::EdDSA), &claims(300), &enc).unwrap();
        let data: TokenData<Value> = decode(&token, &dec, &validation()).unwrap();
        assert_eq!(data.claims["sub"], "alice");
    }

    #[test]
    fn round_trip_es256() {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let secret = p256::SecretKey::random(&mut rand::rngs::OsRng);
        let point = secret.public_key().to_encoded_point(false);
        let dec = DecodingKey::from_ec_components(
            &URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            &URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        )
        .unwrap();
        let enc = EncodingKey::P256(Box::new(p256::ecdsa::SigningKey::from(secret)));
        let mut v = Validation::new(Algorithm::ES256);
        v.set_issuer(&["https://idp.example.com"]);
        v.set_audience(&["tf://example.com"]);
        let token = encode(&Header::new(Algorithm::ES256), &claims(300), &enc).unwrap();
        let data: TokenData<Value> = decode(&token, &dec, &v).unwrap();
        assert_eq!(data.claims["sub"], "alice");
    }

    #[test]
    fn tampered_signature_rejected() {
        let (enc, dec) = ed_pair();
        let token = encode(&Header::new(Algorithm::EdDSA), &claims(300), &enc).unwrap();
        let mut bad = token.clone();
        bad.pop();
        bad.push(if token.ends_with('A') { 'B' } else { 'A' });
        let err = decode::<Value>(&bad, &dec, &validation()).unwrap_err();
        assert!(matches!(err, JwsError::BadSignature | JwsError::Malformed(_)));
    }

    #[test]
    fn alg_none_unrepresentable_and_rejected() {
        // A hand-built alg:none token must fail: parse (unknown alg) and
        // allow-list both reject it.
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let payload = URL_SAFE_NO_PAD.encode(br#"{"sub":"alice"}"#);
        let token = format!("{header}.{payload}.");
        let (_, dec) = ed_pair();
        let err = decode::<Value>(&token, &dec, &validation()).unwrap_err();
        assert!(matches!(err, JwsError::UnsupportedAlgorithm(_)));
    }

    #[test]
    fn wrong_alg_for_key_rejected() {
        let (enc, dec) = ed_pair();
        let token = encode(&Header::new(Algorithm::EdDSA), &claims(300), &enc).unwrap();
        // Validation allows ES256 only.
        let mut v = validation();
        v.algorithms = vec![Algorithm::ES256];
        let err = decode::<Value>(&token, &dec, &v).unwrap_err();
        assert!(matches!(err, JwsError::AlgorithmNotAllowed(_)));
    }

    #[test]
    fn expired_token_rejected_with_leeway() {
        let (enc, dec) = ed_pair();
        let token = encode(&Header::new(Algorithm::EdDSA), &claims(-120), &enc).unwrap();
        let err = decode::<Value>(&token, &dec, &validation()).unwrap_err();
        assert!(matches!(err, JwsError::InvalidClaim(_)));
        // Generous leeway lets it pass.
        let mut v = validation();
        v.leeway = 3600;
        assert!(decode::<Value>(&token, &dec, &v).is_ok());
    }

    #[test]
    fn issuer_and_audience_enforced() {
        let (enc, dec) = ed_pair();
        let token = encode(&Header::new(Algorithm::EdDSA), &claims(300), &enc).unwrap();
        let mut v = validation();
        v.set_issuer(&["https://other.example.com"]);
        assert!(decode::<Value>(&token, &dec, &v).is_err());
        let mut v = validation();
        v.set_audience(&["tf://other.example.com"]);
        assert!(decode::<Value>(&token, &dec, &v).is_err());
    }
}
