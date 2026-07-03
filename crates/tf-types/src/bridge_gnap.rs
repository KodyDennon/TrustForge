//! GNAP (RFC 9635) + DPoP (RFC 9449) bridge — Rust mirror of
//! `tools/tf-types-ts/src/core/bridge-gnap.ts`.
//!
//! The bridge does not run an HTTP server; it provides typed shapes for
//! a `start → continue → access` GNAP flow plus DPoP proof verification
//! and ActorIdentity projection from a verified bound access token.

use std::collections::HashMap;

use crate::encoding::URL_SAFE_NO_PAD;
use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::bridge_oauth::{project_jwk_to_public_key, Jwk, Jwks};
use crate::bridges::{Bridge, BridgeError, BridgeKind};
use crate::generated::{
    ActorIdentity, ActorIdentity_IdentityVersion, ActorType, AuthorityRoot, AuthorityRoot_Kind,
    TrustLevel,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GnapKeyDescriptor {
    pub proof: String,
    pub jwk: Jwk,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GnapClient {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub id: Option<String>,
    pub key: GnapKeyDescriptor,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GnapAccessRight {
    Reference(String),
    Object {
        #[serde(skip_serializing_if = "Option::is_none", default)]
        actions: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        locations: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none", default, rename = "type")]
        kind: Option<String>,
    },
}

impl GnapAccessRight {
    pub fn actions(&self) -> Vec<String> {
        match self {
            GnapAccessRight::Reference(s) => vec![s.clone()],
            GnapAccessRight::Object { actions, .. } => actions.clone().unwrap_or_default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GnapAccessTokenRequest {
    pub access: Vec<GnapAccessRight>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GnapGrantRequest {
    pub client: GnapClient,
    pub access_token: GnapAccessTokenRequest,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GnapAccessTokenResponse {
    pub value: String,
    pub bound: bool,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub expires_in: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GnapGrantResponse {
    pub access_token: GnapAccessTokenResponse,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub continue_uri: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GnapBridgeConfig {
    pub bridge_id: String,
    pub trust_domain: String,
    pub issuer: String,
    pub allowed_algorithms: Vec<String>,
    pub jwks: Jwks,
}

#[derive(Clone, Debug)]
pub struct GnapVerifiedGrant {
    pub identity: ActorIdentity,
    pub capabilities: Vec<String>,
    pub client_key_thumbprint: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DpopProofVerification {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub jkt_expected: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub jkt_seen: Option<String>,
}

pub struct GnapBridge {
    cfg: GnapBridgeConfig,
}

impl GnapBridge {
    pub fn new(cfg: GnapBridgeConfig) -> Self {
        GnapBridge { cfg }
    }

    pub fn build_grant_response(
        &self,
        req: &GnapGrantRequest,
        token: &str,
        finish_uri: Option<&str>,
    ) -> Result<GnapGrantResponse, BridgeError> {
        if req.access_token.access.is_empty() {
            return Err(BridgeError::InvalidInput(
                "access_token.access required".into(),
            ));
        }
        if req.client.key.jwk.kty.is_empty() {
            return Err(BridgeError::InvalidInput("client.key.jwk required".into()));
        }
        Ok(GnapGrantResponse {
            access_token: GnapAccessTokenResponse {
                value: token.into(),
                bound: true,
                expires_in: Some(600),
            },
            continue_uri: finish_uri.map(str::to_string),
        })
    }

    pub fn verify_access_token(
        &self,
        token: &str,
        request: &GnapGrantRequest,
    ) -> Result<GnapVerifiedGrant, BridgeError> {
        if token.is_empty() {
            return Err(BridgeError::InvalidInput("missing access token".into()));
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
        let key = decoding_key_for_jwk(jwk)?;
        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[self.cfg.issuer.as_str()]);
        validation.algorithms = vec![header.alg];
        validation.validate_aud = false;
        let data = decode::<HashMap<String, Value>>(token, &key, &validation).map_err(|e| {
            BridgeError::Rejected(format!("GNAP access token verify failed: {}", e))
        })?;
        let claims = data.claims;
        let expected_jkt = jwk_thumbprint(&request.client.key.jwk)?;
        if let Some(cnf) = claims.get("cnf").and_then(|v| v.as_object()) {
            if let Some(jkt) = cnf.get("jkt").and_then(|v| v.as_str()) {
                if jkt != expected_jkt {
                    return Err(BridgeError::Rejected(
                        "access token cnf.jkt does not match client.key".into(),
                    ));
                }
            }
        }
        let subject = claims
            .get("sub")
            .and_then(|v| v.as_str())
            .unwrap_or("anonymous")
            .to_string();
        let actor_type_str = claims
            .get("tf_actor_type")
            .and_then(|v| v.as_str())
            .unwrap_or("agent")
            .to_string();
        let actor_type = match actor_type_str.as_str() {
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
        let actor_id = format!(
            "tf:actor:{}:{}/{}",
            actor_type_str,
            self.cfg.trust_domain,
            url_encode(&subject)
        );
        let actions: Vec<String> = request
            .access_token
            .access
            .iter()
            .flat_map(|r| r.actions())
            .collect();
        let identity = ActorIdentity {
            identity_version: ActorIdentity_IdentityVersion::V1,
            actor_id,
            actor_type,
            instance_id: None,
            public_keys: vec![project_jwk_to_public_key(&request.client.key.jwk)?],
            trust_levels: vec![TrustLevel::T3],
            authority_roots: vec![AuthorityRoot {
                kind: AuthorityRoot_Kind::Organization,
                id: self.cfg.issuer.clone(),
            }],
            attestations: None,
            valid_from: claims
                .get("iat")
                .and_then(|v| v.as_u64())
                .map(timestamp)
                .unwrap_or_else(|| timestamp(now_unix())),
            valid_until: claims.get("exp").and_then(|v| v.as_u64()).map(timestamp),
            revocation_ref: None,
            signature: None,
        };
        Ok(GnapVerifiedGrant {
            identity,
            capabilities: actions,
            client_key_thumbprint: expected_jkt,
        })
    }

    pub fn verify_dpop_proof(
        &self,
        proof_jwt: &str,
        htm: &str,
        htu: &str,
        access_token_hash: Option<&str>,
        expected_jkt: &str,
    ) -> DpopProofVerification {
        if proof_jwt.is_empty() {
            return DpopProofVerification {
                ok: false,
                reason: Some("missing DPoP proof".into()),
                jkt_expected: Some(expected_jkt.into()),
                jkt_seen: None,
            };
        }
        let parts: Vec<&str> = proof_jwt.split('.').collect();
        if parts.len() != 3 {
            return DpopProofVerification {
                ok: false,
                reason: Some("DPoP proof not a JWT".into()),
                jkt_expected: Some(expected_jkt.into()),
                jkt_seen: None,
            };
        }
        let header_bytes = match URL_SAFE_NO_PAD.decode(parts[0]) {
            Ok(b) => b,
            Err(e) => {
                return DpopProofVerification {
                    ok: false,
                    reason: Some(format!("DPoP header decode: {}", e)),
                    jkt_expected: Some(expected_jkt.into()),
                    jkt_seen: None,
                }
            }
        };
        let header: Value = match serde_json::from_slice(&header_bytes) {
            Ok(v) => v,
            Err(e) => {
                return DpopProofVerification {
                    ok: false,
                    reason: Some(format!("DPoP header parse: {}", e)),
                    jkt_expected: Some(expected_jkt.into()),
                    jkt_seen: None,
                }
            }
        };
        if header.get("typ").and_then(|v| v.as_str()) != Some("dpop+jwt") {
            return DpopProofVerification {
                ok: false,
                reason: Some(format!("DPoP typ {:?} is not dpop+jwt", header.get("typ"))),
                jkt_expected: Some(expected_jkt.into()),
                jkt_seen: None,
            };
        }
        let jwk_value = match header.get("jwk") {
            Some(v) => v,
            None => {
                return DpopProofVerification {
                    ok: false,
                    reason: Some("DPoP header missing jwk".into()),
                    jkt_expected: Some(expected_jkt.into()),
                    jkt_seen: None,
                }
            }
        };
        let jwk: Jwk = match serde_json::from_value(jwk_value.clone()) {
            Ok(v) => v,
            Err(e) => {
                return DpopProofVerification {
                    ok: false,
                    reason: Some(format!("DPoP jwk parse: {}", e)),
                    jkt_expected: Some(expected_jkt.into()),
                    jkt_seen: None,
                }
            }
        };
        let jkt = match jwk_thumbprint(&jwk) {
            Ok(s) => s,
            Err(e) => {
                return DpopProofVerification {
                    ok: false,
                    reason: Some(format!("DPoP thumbprint: {}", e)),
                    jkt_expected: Some(expected_jkt.into()),
                    jkt_seen: None,
                }
            }
        };
        if jkt != expected_jkt {
            return DpopProofVerification {
                ok: false,
                reason: Some("jkt mismatch".into()),
                jkt_expected: Some(expected_jkt.into()),
                jkt_seen: Some(jkt),
            };
        }
        let key = match decoding_key_for_jwk(&jwk) {
            Ok(k) => k,
            Err(e) => {
                return DpopProofVerification {
                    ok: false,
                    reason: Some(format!("DPoP key build: {}", e)),
                    jkt_expected: Some(expected_jkt.into()),
                    jkt_seen: Some(jkt),
                }
            }
        };
        let alg_name = header
            .get("alg")
            .and_then(|v| v.as_str())
            .unwrap_or("ES256");
        let alg = match crate::bridge_oauth::parse_algorithm(alg_name) {
            Ok(a) => a,
            Err(e) => {
                return DpopProofVerification {
                    ok: false,
                    reason: Some(format!("DPoP alg parse: {}", e)),
                    jkt_expected: Some(expected_jkt.into()),
                    jkt_seen: Some(jkt),
                }
            }
        };
        let mut validation = Validation::new(alg);
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        validation.validate_aud = false;
        validation.algorithms = vec![alg];
        let payload = match decode::<HashMap<String, Value>>(proof_jwt, &key, &validation) {
            Ok(d) => d.claims,
            Err(e) => {
                return DpopProofVerification {
                    ok: false,
                    reason: Some(format!("DPoP signature verify failed: {}", e)),
                    jkt_expected: Some(expected_jkt.into()),
                    jkt_seen: Some(jkt),
                }
            }
        };
        if payload.get("htm").and_then(|v| v.as_str()) != Some(htm) {
            return DpopProofVerification {
                ok: false,
                reason: Some(format!(
                    "DPoP htm {:?} does not match expected {}",
                    payload.get("htm"),
                    htm
                )),
                jkt_expected: Some(expected_jkt.into()),
                jkt_seen: Some(jkt),
            };
        }
        if payload.get("htu").and_then(|v| v.as_str()) != Some(htu) {
            return DpopProofVerification {
                ok: false,
                reason: Some(format!(
                    "DPoP htu {:?} does not match expected {}",
                    payload.get("htu"),
                    htu
                )),
                jkt_expected: Some(expected_jkt.into()),
                jkt_seen: Some(jkt),
            };
        }
        if let Some(expected_ath) = access_token_hash {
            if payload.get("ath").and_then(|v| v.as_str()) != Some(expected_ath) {
                return DpopProofVerification {
                    ok: false,
                    reason: Some("DPoP ath does not match expected access-token hash".into()),
                    jkt_expected: Some(expected_jkt.into()),
                    jkt_seen: Some(jkt),
                };
            }
        }
        if !payload.get("iat").map(|v| v.is_number()).unwrap_or(false) {
            return DpopProofVerification {
                ok: false,
                reason: Some("DPoP missing iat".into()),
                jkt_expected: Some(expected_jkt.into()),
                jkt_seen: Some(jkt),
            };
        }
        DpopProofVerification {
            ok: true,
            reason: None,
            jkt_expected: Some(expected_jkt.into()),
            jkt_seen: Some(jkt),
        }
    }
}

impl Bridge for GnapBridge {
    fn bridge_id(&self) -> &str {
        &self.cfg.bridge_id
    }
    fn kind(&self) -> BridgeKind {
        BridgeKind::Gnap
    }
    fn trust_domain(&self) -> &str {
        &self.cfg.trust_domain
    }
}

fn decoding_key_for_jwk(jwk: &Jwk) -> Result<DecodingKey, BridgeError> {
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

/// Compute the RFC 7638 thumbprint of a JWK using SHA-256. The mandatory
/// member set is per RFC 7638 §3.2: kty + key-specific set in
/// lexicographic order.
pub fn jwk_thumbprint(jwk: &Jwk) -> Result<String, BridgeError> {
    let canonical = match jwk.kty.as_str() {
        "EC" => {
            let crv = jwk
                .crv
                .as_ref()
                .ok_or_else(|| BridgeError::InvalidInput("EC JWK missing crv".into()))?;
            let x = jwk
                .x
                .as_ref()
                .ok_or_else(|| BridgeError::InvalidInput("EC JWK missing x".into()))?;
            let y = jwk
                .y
                .as_ref()
                .ok_or_else(|| BridgeError::InvalidInput("EC JWK missing y".into()))?;
            format!(
                "{{\"crv\":\"{}\",\"kty\":\"{}\",\"x\":\"{}\",\"y\":\"{}\"}}",
                crv, jwk.kty, x, y
            )
        }
        "OKP" => {
            let crv = jwk
                .crv
                .as_ref()
                .ok_or_else(|| BridgeError::InvalidInput("OKP JWK missing crv".into()))?;
            let x = jwk
                .x
                .as_ref()
                .ok_or_else(|| BridgeError::InvalidInput("OKP JWK missing x".into()))?;
            format!(
                "{{\"crv\":\"{}\",\"kty\":\"{}\",\"x\":\"{}\"}}",
                crv, jwk.kty, x
            )
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
            format!(
                "{{\"e\":\"{}\",\"kty\":\"{}\",\"n\":\"{}\"}}",
                e, jwk.kty, n
            )
        }
        other => {
            return Err(BridgeError::Unsupported(format!(
                "unsupported kty for thumbprint: {}",
                other
            )))
        }
    };
    let digest: [u8; 32] = Sha256::digest(canonical.as_bytes()).into();
    Ok(URL_SAFE_NO_PAD.encode(digest))
}

fn timestamp(t: u64) -> String {
    let secs = t as i64;
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
    let days = secs.div_euclid(86_400);
    let time = secs.rem_euclid(86_400);
    let hour = (time / 3600) as u32;
    let minute = ((time % 3600) / 60) as u32;
    let second = (time % 60) as u32;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
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

fn url_encode(s: &str) -> String {
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
