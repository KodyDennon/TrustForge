//! DID (W3C DID Core 1.0) bridge — Rust mirror of TS.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::bridges::{Bridge, BridgeError, BridgeKind};
use crate::generated::{
    ActorIdentity, ActorIdentity_IdentityVersion, ActorType, AuthorityRoot, AuthorityRoot_Kind,
    PublicKey, PublicKey_Purpose, TrustLevel,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DidVerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub controller: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key_multibase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key_jwk: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DidDocument {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_method: Option<Vec<DidVerificationMethod>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication: Option<Vec<Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller: Option<Value>,
}

#[derive(Clone, Debug, Default)]
pub struct DidBridgeConfig {
    pub bridge_id: String,
    pub trust_domain: String,
    pub allowed_methods: Option<Vec<String>>,
}

pub struct DidBridge {
    cfg: DidBridgeConfig,
}

impl DidBridge {
    pub fn new(cfg: DidBridgeConfig) -> Self {
        DidBridge { cfg }
    }

    pub fn resolve_did_key(&self, did_url: &str) -> Result<DidDocument, BridgeError> {
        let method = parse_did_method(did_url)?;
        if let Some(allow) = &self.cfg.allowed_methods {
            if !allow.iter().any(|m| m == method) {
                return Err(BridgeError::Rejected(format!(
                    "DID method {} not in allow-list",
                    method
                )));
            }
        }
        if method != "key" {
            return Err(BridgeError::Unsupported(format!(
                "method {} not supported by built-in resolver; provide a custom resolver",
                method
            )));
        }
        let multibase = did_url
            .strip_prefix("did:key:")
            .ok_or_else(|| BridgeError::InvalidInput(format!("not did:key: {}", did_url)))?;
        let id = format!("did:key:{}", multibase);
        Ok(DidDocument {
            id: id.clone(),
            verification_method: Some(vec![DidVerificationMethod {
                id: format!("{}#{}", id, multibase),
                kind: "Ed25519VerificationKey2020".into(),
                controller: id.clone(),
                public_key_multibase: Some(multibase.to_string()),
                public_key_jwk: None,
            }]),
            authentication: Some(vec![Value::String(format!("{}#{}", id, multibase))]),
            controller: Some(Value::String(id)),
        })
    }

    pub fn accept(&self, document: &DidDocument) -> Result<ActorIdentity, BridgeError> {
        let vms = document
            .verification_method
            .as_ref()
            .ok_or_else(|| BridgeError::Rejected("DID has no verification methods".into()))?;
        if vms.is_empty() {
            return Err(BridgeError::Rejected(
                "DID verification_method is empty".into(),
            ));
        }
        let vm = &vms[0];
        let pk = extract_public_key(vm).ok_or_else(|| {
            BridgeError::Unsupported(format!("vm {} has no usable public key", vm.id))
        })?;
        let actor_id = format!(
            "tf:actor:human:{}/{}",
            self.cfg.trust_domain,
            url_encode(&document.id)
        );
        Ok(ActorIdentity {
            identity_version: ActorIdentity_IdentityVersion::V1,
            actor_id,
            actor_type: ActorType::Human,
            instance_id: None,
            public_keys: vec![PublicKey {
                key_id: vm.id.clone(),
                algorithm: pk.algorithm,
                public_key: base64::engine::general_purpose::STANDARD.encode(&pk.bytes),
                purpose: PublicKey_Purpose::Signing,
                valid_from: None,
                valid_until: None,
            }],
            trust_levels: vec![TrustLevel::T2],
            authority_roots: vec![AuthorityRoot {
                kind: AuthorityRoot_Kind::Federation,
                id: vm.controller.clone(),
            }],
            attestations: None,
            valid_from: now_iso8601(),
            valid_until: None,
            revocation_ref: None,
            signature: None,
        })
    }
}

impl Bridge for DidBridge {
    fn bridge_id(&self) -> &str {
        &self.cfg.bridge_id
    }
    fn kind(&self) -> BridgeKind {
        BridgeKind::Did
    }
    fn trust_domain(&self) -> &str {
        &self.cfg.trust_domain
    }
}

struct ProjectedKey {
    algorithm: String,
    bytes: Vec<u8>,
}

fn extract_public_key(vm: &DidVerificationMethod) -> Option<ProjectedKey> {
    if let Some(mb) = &vm.public_key_multibase {
        let decoded = decode_multibase(mb)?;
        if decoded.len() >= 2 && decoded[0] == 0xed && decoded[1] == 0x01 {
            return Some(ProjectedKey {
                algorithm: "ed25519".into(),
                bytes: decoded[2..].to_vec(),
            });
        }
        return Some(ProjectedKey {
            algorithm: vm.kind.to_lowercase(),
            bytes: decoded,
        });
    }
    if let Some(jwk) = &vm.public_key_jwk {
        if jwk.get("kty").and_then(Value::as_str) == Some("OKP")
            && jwk.get("crv").and_then(Value::as_str) == Some("Ed25519")
        {
            if let Some(x) = jwk.get("x").and_then(Value::as_str) {
                let bytes = URL_SAFE_NO_PAD.decode(x).ok()?;
                return Some(ProjectedKey {
                    algorithm: "ed25519".into(),
                    bytes,
                });
            }
        }
    }
    None
}

fn parse_did_method(did: &str) -> Result<&str, BridgeError> {
    let rest = did
        .strip_prefix("did:")
        .ok_or_else(|| BridgeError::InvalidInput(format!("not a DID: {}", did)))?;
    let end = rest
        .find(':')
        .ok_or_else(|| BridgeError::InvalidInput(format!("not a DID: {}", did)))?;
    Ok(&rest[..end])
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

fn decode_multibase(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() {
        return None;
    }
    let prefix = s.as_bytes()[0];
    let body = &s[1..];
    match prefix {
        b'z' => base58btc_decode(body),
        b'm' => base64::engine::general_purpose::STANDARD.decode(body).ok(),
        b'u' => URL_SAFE_NO_PAD.decode(body).ok(),
        _ => None,
    }
}

const BASE58_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn base58btc_decode(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() {
        return Some(Vec::new());
    }
    let mut zeros = 0usize;
    while zeros < s.len() && s.as_bytes()[zeros] == b'1' {
        zeros += 1;
    }
    let size = ((s.len() - zeros) as f64 * 0.733).ceil() as usize + 1;
    let mut b256 = vec![0u8; size];
    for i in zeros..s.len() {
        let c = s.as_bytes()[i];
        let idx = BASE58_ALPHABET.iter().position(|&b| b == c)?;
        let mut carry = idx;
        for j in (0..size).rev() {
            carry += b256[j] as usize * 58;
            b256[j] = (carry & 0xff) as u8;
            carry >>= 8;
        }
        if carry != 0 {
            return None;
        }
    }
    let mut start = 0usize;
    while start < size && b256[start] == 0 {
        start += 1;
    }
    let mut out = vec![0u8; zeros];
    out.extend_from_slice(&b256[start..]);
    Some(out)
}

pub fn ed25519_public_key_to_did_key(pub_bytes: &[u8]) -> Result<String, BridgeError> {
    if pub_bytes.len() != 32 {
        return Err(BridgeError::InvalidInput(format!(
            "ed25519 public key must be 32 bytes, got {}",
            pub_bytes.len()
        )));
    }
    let mut prefixed = Vec::with_capacity(2 + 32);
    prefixed.push(0xed);
    prefixed.push(0x01);
    prefixed.extend_from_slice(pub_bytes);
    Ok(format!("z{}", base58btc_encode(&prefixed)))
}

fn base58btc_encode(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let mut zeros = 0usize;
    while zeros < bytes.len() && bytes[zeros] == 0 {
        zeros += 1;
    }
    let size = ((bytes.len() as f64) * 1.366).ceil() as usize + 1;
    let mut b58 = vec![0u8; size];
    for &byte in bytes.iter().skip(zeros) {
        let mut carry = byte as usize;
        for j in (0..size).rev() {
            carry += b58[j] as usize * 256;
            b58[j] = (carry % 58) as u8;
            carry /= 58;
        }
    }
    let mut start = 0usize;
    while start < size && b58[start] == 0 {
        start += 1;
    }
    let mut out = String::new();
    for _ in 0..zeros {
        out.push('1');
    }
    for &b in &b58[start..] {
        out.push(BASE58_ALPHABET[b as usize] as char);
    }
    out
}

fn now_iso8601() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let (y, m, d, h, mi, s) = secs_to_ymdhms(secs);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, h, mi, s)
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
