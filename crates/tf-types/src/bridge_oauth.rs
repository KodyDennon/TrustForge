//! OAuth/GNAP bridge — verify a JWT bearer token using `jsonwebtoken`,
//! against a static or remote JWKS, and project the verified claims into a
//! TrustForge actor identity + capabilities.
//!
//! Supports ES256 / ES384 / RS256 / RS384 / RS512 / EdDSA. Algorithm
//! confusion attacks (alg:none, HS256-with-RSA-key) are guarded by the
//! mandatory allow-list passed at bridge construction time.

use std::collections::HashMap;

use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::bridges::{Bridge, BridgeError, BridgeKind};
use crate::generated::{
    ActorIdentity, ActorIdentity_IdentityVersion, ActorType, AuthorityRoot, AuthorityRoot_Kind,
    PublicKey, PublicKey_Purpose, TrustLevel,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OAuthBridgeConfig {
    pub bridge_id: String,
    pub trust_domain: String,
    pub jwks: Jwks,
    pub allowed_algorithms: Vec<String>,
    pub issuer: String,
    pub audience: Vec<String>,
    #[serde(default = "default_clock_tolerance")]
    pub clock_tolerance_seconds: u64,
}

fn default_clock_tolerance() -> u64 {
    60
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

/// Minimal JWK shape the bridge accepts. ES256/ES384 use x/y; RS* use n/e;
/// EdDSA uses crv=Ed25519 + x.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(default)]
    pub kid: Option<String>,
    #[serde(default)]
    pub crv: Option<String>,
    #[serde(default)]
    pub x: Option<String>,
    #[serde(default)]
    pub y: Option<String>,
    #[serde(default)]
    pub n: Option<String>,
    #[serde(default)]
    pub e: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OAuthClaims {
    pub iss: Option<String>,
    pub sub: Option<String>,
    pub aud: Option<Value>,
    pub exp: Option<u64>,
    pub iat: Option<u64>,
    pub scope: Option<Value>,
    #[serde(rename = "tf_actor_type", default)]
    pub tf_actor_type: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Clone, Debug)]
pub struct OAuthVerificationResult {
    pub identity: ActorIdentity,
    pub capabilities: Vec<String>,
    pub claims: OAuthClaims,
}

pub struct OAuthBridge {
    cfg: OAuthBridgeConfig,
}

impl OAuthBridge {
    pub fn new(cfg: OAuthBridgeConfig) -> Self {
        OAuthBridge { cfg }
    }

    pub fn verify_token(&self, token: &str) -> Result<OAuthVerificationResult, BridgeError> {
        if token.is_empty() {
            return Err(BridgeError::InvalidInput("empty token".into()));
        }
        let header = decode_header(token)
            .map_err(|e| BridgeError::Rejected(format!("malformed JWT: {}", e)))?;
        let alg_name = format!("{:?}", header.alg);
        if !self
            .cfg
            .allowed_algorithms
            .iter()
            .any(|a| a.eq_ignore_ascii_case(&alg_name))
        {
            return Err(BridgeError::Rejected(format!(
                "algorithm {} not in allow-list",
                alg_name
            )));
        }

        let kid = header
            .kid
            .clone()
            .ok_or_else(|| BridgeError::Rejected("JWT header missing kid".into()))?;
        let jwk = self
            .cfg
            .jwks
            .keys
            .iter()
            .find(|k| k.kid.as_deref() == Some(&kid))
            .ok_or_else(|| BridgeError::Rejected(format!("no JWK with kid {}", kid)))?;
        let key = decoding_key_for(jwk)?;

        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[self.cfg.issuer.as_str()]);
        validation.set_audience(&self.cfg.audience);
        validation.leeway = self.cfg.clock_tolerance_seconds;
        validation.algorithms = vec![header.alg];

        let data = decode::<OAuthClaims>(token, &key, &validation)
            .map_err(|e| BridgeError::Rejected(format!("JWT verify failed: {}", e)))?;
        let claims = data.claims;
        let subject = claims
            .sub
            .clone()
            .ok_or_else(|| BridgeError::Rejected("JWT missing sub claim".into()))?;
        let actor_type_str = claims.tf_actor_type.as_deref().unwrap_or("human");
        let actor_type = match actor_type_str {
            "human" => ActorType::Human,
            "agent" => ActorType::Agent,
            "device" => ActorType::Device,
            "service" => ActorType::Service,
            "site" => ActorType::Site,
            "organization" => ActorType::Organization,
            other => {
                return Err(BridgeError::Rejected(format!(
                    "unsupported tf_actor_type: {}",
                    other
                )))
            }
        };
        let encoded_subject = encode_subject(&subject);
        let actor_id = format!(
            "tf:actor:{}:{}/{}",
            actor_type_str, self.cfg.trust_domain, encoded_subject
        );

        let identity = ActorIdentity {
            identity_version: ActorIdentity_IdentityVersion::V1,
            actor_id,
            actor_type,
            instance_id: None,
            public_keys: vec![project_jwk_to_public_key(jwk)?],
            trust_levels: vec![TrustLevel::T3],
            authority_roots: vec![AuthorityRoot {
                kind: AuthorityRoot_Kind::Organization,
                id: self.cfg.issuer.clone(),
            }],
            attestations: None,
            valid_from: claims
                .iat
                .map(|t| timestamp(t))
                .unwrap_or_else(|| timestamp(now_unix())),
            valid_until: claims.exp.map(timestamp),
            revocation_ref: None,
            signature: None,
        };

        let capabilities = scopes_from_claims(&claims);

        Ok(OAuthVerificationResult {
            identity,
            capabilities,
            claims,
        })
    }
}

impl Bridge for OAuthBridge {
    fn bridge_id(&self) -> &str {
        &self.cfg.bridge_id
    }
    fn kind(&self) -> BridgeKind {
        BridgeKind::Oauth
    }
    fn trust_domain(&self) -> &str {
        &self.cfg.trust_domain
    }
}

fn decoding_key_for(jwk: &Jwk) -> Result<DecodingKey, BridgeError> {
    match jwk.kty.as_str() {
        "EC" => {
            let x = jwk
                .x
                .as_ref()
                .ok_or_else(|| BridgeError::InvalidInput("EC JWK missing x".into()))?;
            let y = jwk
                .y
                .as_ref()
                .ok_or_else(|| BridgeError::InvalidInput("EC JWK missing y".into()))?;
            DecodingKey::from_ec_components(x, y)
                .map_err(|e| BridgeError::InvalidInput(format!("bad EC components: {}", e)))
        }
        "RSA" => {
            let n = jwk
                .n
                .as_ref()
                .ok_or_else(|| BridgeError::InvalidInput("RSA JWK missing n".into()))?;
            let e = jwk
                .e
                .as_ref()
                .ok_or_else(|| BridgeError::InvalidInput("RSA JWK missing e".into()))?;
            DecodingKey::from_rsa_components(n, e)
                .map_err(|e| BridgeError::InvalidInput(format!("bad RSA components: {}", e)))
        }
        "OKP" => {
            let x = jwk
                .x
                .as_ref()
                .ok_or_else(|| BridgeError::InvalidInput("OKP JWK missing x".into()))?;
            DecodingKey::from_ed_components(x)
                .map_err(|e| BridgeError::InvalidInput(format!("bad OKP components: {}", e)))
        }
        other => Err(BridgeError::InvalidInput(format!(
            "unsupported kty {}",
            other
        ))),
    }
}

fn encode_subject(s: &str) -> String {
    // Percent-encode anything outside the unreserved RFC 3986 set so the
    // subject can be embedded in an actor URI path segment.
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

fn scopes_from_claims(claims: &OAuthClaims) -> Vec<String> {
    match &claims.scope {
        Some(Value::String(s)) => s.split_whitespace().map(str::to_string).collect(),
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

fn timestamp(t: u64) -> String {
    // Format as RFC 3339 UTC.
    let datetime = std::time::UNIX_EPOCH + std::time::Duration::from_secs(t);
    let secs = datetime
        .duration_since(std::time::UNIX_EPOCH)
        .expect("post-epoch")
        .as_secs() as i64;
    // Build YYYY-MM-DDTHH:MM:SSZ from secs without bringing chrono in.
    let (year, month, day, hour, minute, second) = secs_to_ymdhms(secs);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, minute, second
    )
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn secs_to_ymdhms(secs: i64) -> (i32, u32, u32, u32, u32, u32) {
    // Civil-from-days algorithm by Howard Hinnant.
    let days = secs.div_euclid(86_400);
    let time = secs.rem_euclid(86_400);
    let hour = (time / 3600) as u32;
    let minute = ((time % 3600) / 60) as u32;
    let second = (time % 60) as u32;

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 {
        (mp + 3) as u32
    } else {
        (mp - 9) as u32
    };
    let year = if m <= 2 { y + 1 } else { y };
    (year as i32, m, d, hour, minute, second)
}

pub fn parse_algorithm(name: &str) -> Result<Algorithm, BridgeError> {
    match name.to_ascii_uppercase().as_str() {
        "ES256" => Ok(Algorithm::ES256),
        "ES384" => Ok(Algorithm::ES384),
        "RS256" => Ok(Algorithm::RS256),
        "RS384" => Ok(Algorithm::RS384),
        "RS512" => Ok(Algorithm::RS512),
        "EDDSA" => Ok(Algorithm::EdDSA),
        other => Err(BridgeError::InvalidInput(format!(
            "unsupported algorithm: {}",
            other
        ))),
    }
}

/// Project a JWK into the TrustForge `PublicKey` shape (raw bytes,
/// base64-encoded, with the algorithm name normalised to TrustForge's
/// vocabulary). Mirrors the TS `projectJwkToPublicKey`.
pub fn project_jwk_to_public_key(jwk: &Jwk) -> Result<PublicKey, BridgeError> {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use base64::Engine;
    let key_id = jwk
        .kid
        .clone()
        .unwrap_or_else(|| "oauth-bridge-bearer".to_string());
    match jwk.kty.as_str() {
        "OKP" => {
            // Ed25519 — raw 32-byte x.
            let x = jwk
                .x
                .as_ref()
                .ok_or_else(|| BridgeError::InvalidInput("OKP JWK missing x".into()))?;
            let bytes = URL_SAFE_NO_PAD
                .decode(x)
                .map_err(|e| BridgeError::InvalidInput(format!("base64url x: {}", e)))?;
            Ok(PublicKey {
                key_id,
                algorithm: "ed25519".into(),
                public_key: STANDARD.encode(bytes),
                purpose: PublicKey_Purpose::Signing,
                valid_from: None,
                valid_until: None,
            })
        }
        "EC" => {
            let x = jwk
                .x
                .as_ref()
                .ok_or_else(|| BridgeError::InvalidInput("EC JWK missing x".into()))?;
            let y = jwk
                .y
                .as_ref()
                .ok_or_else(|| BridgeError::InvalidInput("EC JWK missing y".into()))?;
            let xb = URL_SAFE_NO_PAD
                .decode(x)
                .map_err(|e| BridgeError::InvalidInput(format!("base64url x: {}", e)))?;
            let yb = URL_SAFE_NO_PAD
                .decode(y)
                .map_err(|e| BridgeError::InvalidInput(format!("base64url y: {}", e)))?;
            let mut sec1 = Vec::with_capacity(1 + xb.len() + yb.len());
            sec1.push(0x04);
            sec1.extend_from_slice(&xb);
            sec1.extend_from_slice(&yb);
            let crv = jwk.crv.as_deref().unwrap_or("");
            let alg = match crv {
                "P-256" => "p256",
                "P-384" => "p384",
                "P-521" => "p521",
                _ => "ec",
            };
            Ok(PublicKey {
                key_id,
                algorithm: alg.into(),
                public_key: STANDARD.encode(sec1),
                purpose: PublicKey_Purpose::Signing,
                valid_from: None,
                valid_until: None,
            })
        }
        "RSA" => {
            let n = jwk
                .n
                .as_ref()
                .ok_or_else(|| BridgeError::InvalidInput("RSA JWK missing n".into()))?;
            let e = jwk
                .e
                .as_ref()
                .ok_or_else(|| BridgeError::InvalidInput("RSA JWK missing e".into()))?;
            let nb = URL_SAFE_NO_PAD
                .decode(n)
                .map_err(|err| BridgeError::InvalidInput(format!("base64url n: {}", err)))?;
            let eb = URL_SAFE_NO_PAD
                .decode(e)
                .map_err(|err| BridgeError::InvalidInput(format!("base64url e: {}", err)))?;
            let der = encode_rsa_spki(&nb, &eb);
            Ok(PublicKey {
                key_id,
                algorithm: "rsa".into(),
                public_key: STANDARD.encode(der),
                purpose: PublicKey_Purpose::Signing,
                valid_from: None,
                valid_until: None,
            })
        }
        other => Err(BridgeError::Unsupported(format!(
            "unsupported JWK kty: {}",
            other
        ))),
    }
}

fn encode_rsa_spki(n: &[u8], e: &[u8]) -> Vec<u8> {
    let rsa_public_key = der_sequence(&[der_integer(n), der_integer(e)]);
    let oid_rsa_encryption: [u8; 11] = [
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
    ];
    let null_params: [u8; 2] = [0x05, 0x00];
    let alg_id = der_sequence(&[oid_rsa_encryption.to_vec(), null_params.to_vec()]);
    let mut bit_string_body = Vec::with_capacity(1 + rsa_public_key.len());
    bit_string_body.push(0x00);
    bit_string_body.extend_from_slice(&rsa_public_key);
    let mut bit_string = Vec::with_capacity(2 + bit_string_body.len());
    bit_string.push(0x03);
    bit_string.extend_from_slice(&der_len(bit_string_body.len()));
    bit_string.extend_from_slice(&bit_string_body);
    der_sequence(&[alg_id, bit_string])
}

fn der_sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    let body: Vec<u8> = parts.iter().flat_map(|p| p.clone()).collect();
    let mut out = Vec::with_capacity(2 + body.len());
    out.push(0x30);
    out.extend_from_slice(&der_len(body.len()));
    out.extend_from_slice(&body);
    out
}

fn der_integer(bytes: &[u8]) -> Vec<u8> {
    let mut start = 0usize;
    while start < bytes.len() - 1 && bytes[start] == 0 {
        start += 1;
    }
    let payload = &bytes[start..];
    let needs_pad = payload[0] & 0x80 != 0;
    let len = payload.len() + if needs_pad { 1 } else { 0 };
    let mut out = Vec::with_capacity(2 + len);
    out.push(0x02);
    out.extend_from_slice(&der_len(len));
    if needs_pad {
        out.push(0x00);
    }
    out.extend_from_slice(payload);
    out
}

fn der_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        return vec![n as u8];
    }
    let mut bytes = Vec::new();
    let mut v = n;
    while v > 0 {
        bytes.insert(0, (v & 0xff) as u8);
        v >>= 8;
    }
    let mut out = Vec::with_capacity(1 + bytes.len());
    out.push(0x80 | bytes.len() as u8);
    out.extend_from_slice(&bytes);
    out
}
