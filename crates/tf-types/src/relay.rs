//! Relay model — Rust mirror of `tools/tf-types-ts/src/core/relay.ts`.
//! Forwarding authority is strictly separate from action authority;
//! `RelayHandler` only sees opaque ciphertext and routes it.

use crate::encoding::STANDARD;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::canonicalize;
use crate::expiration::{is_within_window, Window};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayAuthority {
    pub relay_authority_version: String,
    pub relay: String,
    pub trust_domain: String,
    pub kinds: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub max_hop_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub rate_limit_per_minute: Option<u32>,
    pub valid_from: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub valid_until: Option<String>,
    pub issuer: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub constraints: Option<Vec<Value>>,
    pub signature: SignatureEnvelope,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignatureEnvelope {
    pub algorithm: String,
    pub signer: String,
    pub signature: String,
}

#[derive(Clone, Debug, Default)]
pub struct RelayFrame {
    pub ciphertext: Vec<u8>,
    pub destination: String,
    pub priority: Option<String>,
    pub hop_count: u32,
    pub expires_at: Option<String>,
    pub source: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayForwardedEvent {
    #[serde(rename = "type")]
    pub kind: String,
    pub relay: String,
    pub destination: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub source: Option<String>,
    pub hop_count_in: u32,
    pub hop_count_out: u32,
    pub size_bytes: usize,
    pub forwarded_at: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub authority_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub priority: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum RelayPolicyError {
    #[error("relay authority invalid: {0}")]
    Authority(String),
    #[error("authority window: {0}")]
    Window(String),
    #[error("frame expired: {0}")]
    Expired(String),
    #[error("hop count: {0}")]
    HopCap(String),
    #[error("rate limit: {0}")]
    Rate(String),
}

pub struct RelayHandler {
    authority: RelayAuthority,
    issuer_pub: [u8; 32],
    validated: std::cell::Cell<bool>,
    rate_bucket_minute: std::cell::Cell<i64>,
    rate_bucket_count: std::cell::Cell<u32>,
}

impl RelayHandler {
    pub fn new(authority: RelayAuthority, issuer_public_key: [u8; 32]) -> Self {
        RelayHandler {
            authority,
            issuer_pub: issuer_public_key,
            validated: std::cell::Cell::new(false),
            rate_bucket_minute: std::cell::Cell::new(-1),
            rate_bucket_count: std::cell::Cell::new(0),
        }
    }

    pub fn authority(&self) -> &RelayAuthority {
        &self.authority
    }

    pub fn forward(
        &self,
        frame: &RelayFrame,
        now: &str,
    ) -> Result<(RelayFrame, RelayForwardedEvent), RelayPolicyError> {
        if !self.validated.get() {
            let v = verify_relay_authority(&self.authority, &self.issuer_pub);
            if !v.ok {
                return Err(RelayPolicyError::Authority(
                    v.reason.unwrap_or_else(|| "unknown".into()),
                ));
            }
            self.validated.set(true);
        }
        let window = Window {
            valid_from: Some(self.authority.valid_from.as_str()),
            valid_until: self.authority.valid_until.as_deref(),
            ..Window::default()
        };
        if !is_within_window(&window, now) {
            return Err(RelayPolicyError::Window(
                "outside valid_from/valid_until".into(),
            ));
        }
        if let Some(exp) = &frame.expires_at {
            if exp.as_str() < now {
                return Err(RelayPolicyError::Expired(format!(
                    "frame expired at {}",
                    exp
                )));
            }
        }
        if let Some(max) = self.authority.max_hop_count {
            if frame.hop_count >= max {
                return Err(RelayPolicyError::HopCap(format!(
                    "hop count {} >= max {}",
                    frame.hop_count, max
                )));
            }
        }
        if let Some(limit) = self.authority.rate_limit_per_minute {
            let minute = parse_minute(now);
            if minute != self.rate_bucket_minute.get() {
                self.rate_bucket_minute.set(minute);
                self.rate_bucket_count.set(0);
            }
            self.rate_bucket_count.set(self.rate_bucket_count.get() + 1);
            if self.rate_bucket_count.get() > limit {
                return Err(RelayPolicyError::Rate(format!(
                    "rate limit {}/min exceeded",
                    limit
                )));
            }
        }
        let mut outgoing = frame.clone();
        outgoing.hop_count = frame.hop_count + 1;
        let event = RelayForwardedEvent {
            kind: "relay.forwarded".into(),
            relay: self.authority.relay.clone(),
            destination: frame.destination.clone(),
            source: frame.source.clone(),
            hop_count_in: frame.hop_count,
            hop_count_out: outgoing.hop_count,
            size_bytes: frame.ciphertext.len(),
            forwarded_at: now.to_string(),
            authority_id: Some(self.authority.relay.clone()),
            priority: frame.priority.clone(),
        };
        Ok((outgoing, event))
    }
}

fn parse_minute(now: &str) -> i64 {
    // Lexicographic-friendly: "YYYY-MM-DDTHH:MM:SS..."; parse into unix
    // seconds then divide by 60. If parsing fails, return 0 (which makes
    // the rate limiter behave as a single-bucket counter).
    let len = now.len().min(19);
    if !now.is_char_boundary(len) || len < 19 {
        return 0;
    }
    let trimmed = &now[..19];
    let unix = parse_iso8601(trimmed).unwrap_or(0);
    unix / 60
}

fn parse_iso8601(s: &str) -> Option<i64> {
    if s.len() < 19 {
        return None;
    }
    let year: i64 = s.get(0..4)?.parse().ok()?;
    let month: u32 = s.get(5..7)?.parse().ok()?;
    let day: u32 = s.get(8..10)?.parse().ok()?;
    let hour: u32 = s.get(11..13)?.parse().ok()?;
    let minute: u32 = s.get(14..16)?.parse().ok()?;
    let second: u32 = s.get(17..19)?.parse().ok()?;
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let m = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * m as u64 + 2) / 5 + day as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe as i64 - 719_468;
    Some(days * 86_400 + (hour as i64) * 3600 + (minute as i64) * 60 + second as i64)
}

pub fn relay_authority_signing_bytes(a: &RelayAuthority) -> [u8; 32] {
    let mut value = serde_json::to_value(a).unwrap_or(Value::Null);
    if let Value::Object(map) = &mut value {
        map.remove("signature");
    }
    let canonical = canonicalize(&value).unwrap_or_default();
    Sha256::digest(canonical.as_bytes()).into()
}

pub fn sign_relay_authority(
    mut authority: RelayAuthority,
    private_key: &[u8; 32],
) -> RelayAuthority {
    authority.signature = SignatureEnvelope {
        algorithm: "ed25519".into(),
        signer: authority.issuer.clone(),
        signature: String::new(),
    };
    let digest = relay_authority_signing_bytes(&authority);
    let signing = SigningKey::from_bytes(private_key);
    let sig: Signature = signing.sign(&digest);
    authority.signature.signature = STANDARD.encode(sig.to_bytes());
    authority
}

#[derive(Debug)]
pub struct VerifyRelayAuthorityResult {
    pub ok: bool,
    pub reason: Option<String>,
}

pub fn verify_relay_authority(
    authority: &RelayAuthority,
    issuer_public_key: &[u8; 32],
) -> VerifyRelayAuthorityResult {
    let rejected = |r: &str| VerifyRelayAuthorityResult {
        ok: false,
        reason: Some(r.to_string()),
    };
    if authority.relay_authority_version != "1" {
        return rejected(&format!(
            "unsupported version {}",
            authority.relay_authority_version
        ));
    }
    if authority.signature.algorithm != "ed25519" {
        return rejected(&format!(
            "unsupported signature algorithm {}",
            authority.signature.algorithm
        ));
    }
    if authority.signature.signer != authority.issuer {
        return rejected("signature signer does not match authority issuer");
    }
    let digest = relay_authority_signing_bytes(authority);
    let sig_bytes = match STANDARD.decode(&authority.signature.signature) {
        Ok(b) => b,
        Err(e) => return rejected(&format!("signature base64 decode: {}", e)),
    };
    let sig = match Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(e) => return rejected(&format!("signature parse: {}", e)),
    };
    let vk = match VerifyingKey::from_bytes(issuer_public_key) {
        Ok(v) => v,
        Err(e) => return rejected(&format!("verifying key: {}", e)),
    };
    if vk.verify(&digest, &sig).is_err() {
        return rejected("relay authority signature did not verify");
    }
    VerifyRelayAuthorityResult {
        ok: true,
        reason: None,
    }
}
